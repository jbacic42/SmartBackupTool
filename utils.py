import os
import ctypes
import re
import hashlib
from pathlib import Path
from typing import Optional
from datetime import datetime
import sys
import subprocess
import platform
import shlex
import base64
import logging

# Configuration constants
CONFIG_FILE = Path(".backup_config.json")
LOG_FILENAME = ".backup_operations.log"
MD5_CHUNK_SIZE = 1048576
CLI_BASE_NAME = "SBcli"

def _get_app_root() -> Path:
    """Returns the application root directory for both frozen and script contexts."""
    if getattr(sys, 'frozen', False):
        return Path(sys.argv[0]).parent
    else:
        return Path(__file__).parent

def calculate_md5(file_path: Path, chunk_size: int = MD5_CHUNK_SIZE) -> Optional[str]:
    """Calculates the MD5 hash of a file for integrity verification."""
    try:
        hash_md5 = hashlib.md5()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(chunk_size), b''):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception:
        return None

def get_latest_version_in_folder(source_path: Path, dest_path: Path) -> Optional[str]:
    """Identifies the highest version tag among existing archives in the destination."""
    if not source_path or not dest_path or not dest_path.exists():
        return None

    p_name = source_path.name
    max_v_str, max_v_tuple = None, []
    
    try:
        for item in dest_path.iterdir():
            if item.is_file() and item.name.lower().endswith(".zip") and item.name.startswith(p_name):
                tail = item.name[len(p_name):][:-4].lstrip(" _-")
                clean = re.sub(r'^(backup)[ _-]?', '', tail, flags=re.IGNORECASE)
                v_part = re.sub(r'\d{4}-\d{2}-\d{2}', '', clean).lstrip(" _-")
                nums = re.findall(r'\d+', v_part)
                if nums:
                    curr = [int(n) for n in nums]
                    if curr > max_v_tuple:
                        max_v_tuple, max_v_str = curr, v_part 
        return max_v_str
    except Exception:
        return None

def generate_backup_filename(source_path: Path, version: str = "", use_date: bool = False) -> str:
    """Generates a standardized backup filename based on project and version metadata."""
    date_p = datetime.now().strftime("%Y-%m-%d") if use_date else ""
    suffix = f"{date_p}_{version}".strip("_")
    return f"{source_path.name}_backup_{suffix}.zip" if suffix else f"{source_path.name}_backup.zip"

def increment_version_string(v_str: str) -> str:
    """Parses and increments the numeric component of a version string."""
    match = re.search(r'\d', v_str)
    if not match:
        return v_str + "_2"

    first_digit_index = match.start()
    prefix = v_str[:first_digit_index]
    body = v_str[first_digit_index:]

    last_number_match = re.search(r'(\d+)(?=[^\d]*$)', body)
    if last_number_match:
        original_num_str = last_number_match.group(1)
        new_num = int(original_num_str) + 1
        new_num_str = str(new_num).zfill(len(original_num_str))
        
        start_idx, end_idx = last_number_match.span()
        new_body = body[:start_idx] + new_num_str + body[end_idx:]
        return prefix + new_body
    return v_str + "_2"

def validate_backup_paths(src: str, dst: str) -> Optional[str]:
    """Validates existence of source and prevents recursive directory nesting."""
    if not src or not dst:
        return "Please select both Source and Destination folders."
    
    src_path = Path(src).resolve()
    dst_path = Path(dst).resolve()
    
    if not src_path.exists():
        return "Source folder does not exist."
    
    if dst_path == src_path or dst_path.is_relative_to(src_path):
        return "CRITICAL ERROR: Destination cannot be inside the Source folder!"
    
    return None

def set_hidden_windows(path: Path):
    """Sets the Win32 hidden file attribute if applicable."""
    if os.name == 'nt' and path.exists():
        try:
            ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x02)
        except Exception:
            pass

def _schedule_windows(cmd_str: str, interval: str, src: str, dst: str) -> bool:
    """Registers a Windows Task Scheduler entry with a unique ID based on path mapping."""
    interval_map = {
        'hour':  'HOURLY',
        'day':   'DAILY',
        'week':  'WEEKLY',
        'month': 'MONTHLY'
    }
    
    sc_type = interval_map.get(interval.lower(), 'DAILY')
    path_id = hashlib.md5(f"{src}{dst}".encode()).hexdigest()[:8]
    task_name = f"SmartBackup_{path_id}"
    
    current_time = datetime.now().strftime("%H:%M")
    win_cmd = [
            "schtasks", "/Create", "/F",
            "/TN", task_name,
            "/TR", cmd_str,
            "/SC", sc_type,
            "/ST", current_time
        ]
    
    try:
        subprocess.run(win_cmd, shell=True, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Windows Scheduler Error: {e.stderr.decode()}")
        return False

def verify_cli_exists() -> bool:
    """Checks for the presence of the CLI component in the application root."""
    app_root = _get_app_root()
    if getattr(sys, 'frozen', False):
        cli_name = (CLI_BASE_NAME + ".exe") if platform.system() == "Windows" else CLI_BASE_NAME
    else:
        cli_name = CLI_BASE_NAME + ".py"
    
    return (app_root / cli_name).exists()
    
def add_to_scheduler(interval: str, command: str, src: str, dest: str, run_now: bool = True, is_zip: bool = False) -> bool:
    """Registers task in system scheduler and optionally executes an immediate background process."""
    os_type = platform.system()
    app_root = _get_app_root()
    python_exe = Path(sys.executable)
    
    if getattr(sys, 'frozen', False):
        cli_path = app_root / ((CLI_BASE_NAME + ".exe") if os_type == "Windows" else CLI_BASE_NAME)
        exec_cmd = f'"{cli_path}" {command}'
    else:
        script_path = app_root / (CLI_BASE_NAME + ".py")
        exec_cmd = f'"{python_exe}" "{script_path}" {command}'

    if os_type == "Windows":
        return _schedule_windows(exec_cmd, interval, src, dest)
    else:
        scheduled = _schedule_linux(exec_cmd, interval, src, dest)
        if scheduled and run_now:
            log_dir = Path(dest) if is_zip else (Path(dest) / Path(src).name)
            log_file = log_dir / LOG_FILENAME
            log_dir.mkdir(parents=True, exist_ok=True)

            with open(log_file, "a") as log_out:
                subprocess.Popen(
                    shlex.split(exec_cmd),
                    stdout=log_out,
                    stderr=log_out,
                    start_new_session=True
                )
        return scheduled

def _schedule_linux(cmd_str: str, interval: str, src: str, dest: str) -> bool:
    """Configures crontab entries for Linux-based systems."""
    interval = interval.lower()
    intervals = {
        'hour': '0 * * * *', 'day': '0 0 * * *', 
        'week': '0 0 * * 0', 'month': '0 0 1 * *'
    }
    timing = intervals.get(interval, '0 0 * * *')
    new_job = f'{timing} {cmd_str}'
    
    try:
        result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
        lines = result.stdout.splitlines() if result.returncode == 0 else []
        
        src_str = str(Path(src).resolve())
        dst_str = str(Path(dest).resolve())
        
        updated_lines = []
        pattern = re.compile(rf'{re.escape(CLI_BASE_NAME)}.*'rf'"{re.escape(src_str)}/?"\s+'rf'"{re.escape(dst_str)}/?"')
        
        for line in lines:
            if not pattern.search(line):
                updated_lines.append(line)
            
        updated_lines.append(new_job)
        final_cron = "\n".join(updated_lines) + "\n"
        subprocess.run(['crontab', '-'], input=final_cron, text=True, check=True)
        return True
    except Exception as e:
        print(f"Linux Cron Error: {e}")
        return False

def remove_specific_schedule(src: str, dst: str) -> bool:
    """Removes the system scheduler entry matching specific source and destination paths."""
    os_type = platform.system()
    src_p = Path(src).resolve()
    dst_p = Path(dst).resolve()

    if os_type == "Windows":
        path_id = hashlib.md5(f"{src_p}{dst_p}".encode()).hexdigest()[:8]
        task_name = f"SmartBackup_{path_id}"
        
        cmd = f'schtasks /Delete /TN "{task_name}" /F'
        try:
            subprocess.run(cmd, shell=True, capture_output=True)
            return True
        except Exception as e:
            print(f"Windows Task Removal Error: {e}")
            return False
            
    else:
        try:
            result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)

            if result.returncode != 0: 
                print("Crontab schedule file does not exist.")
                return False 
            
            lines = result.stdout.splitlines()
            new_lines = []
            deleted = []
            pattern = re.compile(rf'{re.escape(CLI_BASE_NAME)}.*'rf'"{re.escape(str(src_p))}/?"\s+'rf'"{re.escape(str(dst_p))}/?"')
            for l in lines:
                if pattern.search(l):
                    deleted.append(l)
                else:
                    new_lines.append(l)    

            if not new_lines:
                subprocess.run(['crontab', '-r'], check=True)
            else:
                final_cron = "\n".join(new_lines) + "\n"
                subprocess.run(['crontab', '-'], input=final_cron, text=True, check=True)

            if len(deleted):
                print("Deleted tasks:")    
                for line in deleted:
                    print(line)
                return True
            
            return False
        except Exception as e:
            print(f"Linux Cron Removal Error: {e}")
            return False

def remove_all_schedules() -> bool:
    """Purges all tasks associated with the application from the system scheduler."""
    os_type = platform.system()
    
    if os_type == "Windows":
        try:
            result = subprocess.run(['schtasks', '/Query', '/FO', 'CSV', '/NH'], 
                                    capture_output=True, text=True)
            if result.returncode != 0: return True
            
            for line in result.stdout.splitlines():
                if f'"{CLI_BASE_NAME}_' in line or '"SmartBackup_' in line:
                    task_name = line.split(',')[0].strip('"')
                    subprocess.run(['schtasks', '/Delete', '/TN', task_name, '/F'], 
                                   capture_output=True)
            return True
        except Exception as e:
            print(f"Error clearing Windows tasks: {e}")
            return False
            
    else:
        try:
            result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
            if result.returncode != 0: 
                print("Crontab schedule file does not exist.")
                return False
            
            lines = result.stdout.splitlines()
            new_lines = []
            deleted = []

            for line in lines:
                if line:
                    if CLI_BASE_NAME in line:
                        deleted.append(line)
                    else:
                        new_lines.append(line)

            if not new_lines:
                subprocess.run(['crontab', '-r'], check=True)
            else:
                final_cron = "\n".join(new_lines) + "\n"
                subprocess.run(['crontab', '-'], input=final_cron, text=True, check=True)
            
            if len(deleted):
                print("Deleted tasks:")
                for line in deleted:
                    print(line)
                return True

            return False
        except Exception as e:
            print(f"Error clearing Linux cron: {e}")
            return False

def get_file_list(root_path: Path) -> list[Path]:
    """Recursively crawls the filesystem to build a list of valid file paths."""
    root = Path(root_path)
    stack = [root]
    all_files = []

    while stack:
        current_dir = stack.pop()
        try:
            with os.scandir(current_dir) as entries:
                for entry in entries:
                    if entry.is_symlink():
                        logging.warning(f'Symlink skipped: {entry}')
                        continue

                    if entry.is_dir():
                        stack.append(Path(entry.path))
                    elif entry.is_file():
                        all_files.append(Path(entry.path))
        except PermissionError:
            msg = f"Permission Denied: {current_dir}. Skipping folder."
            logging.warning(msg)
            print(msg) 
        except Exception as e:
            import logging
            logging.error(f"Error accessing {current_dir}: {e}")

    return all_files

def encrypt_password(password: str) -> str:
    """Encodes plaintext password for CLI parameter safety."""
    if not password: return ""
    return base64.b64encode(password.encode()).decode()

def decrypt_password(encoded_str: str) -> str:
    """Decodes Base64 encoded password strings."""
    return base64.b64decode(encoded_str.encode()).decode()