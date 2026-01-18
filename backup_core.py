import logging
import os
import shutil
import pyzipper
from pathlib import Path
from typing import Optional
import utils
import sys

logger = logging.getLogger("SmartBackup")

def setup_logging(log_file_path: Path):
    """Initializes or updates the file and stream logging handlers."""
    log_file_path = log_file_path.resolve()
    
    # Check for existing configuration to prevent redundant initialization
    existing_file_handler = next((h for h in logger.handlers if isinstance(h, logging.FileHandler)), None)
    has_console = any(isinstance(h, logging.StreamHandler) for h in logger.handlers)

    if existing_file_handler:
        if Path(existing_file_handler.baseFilename).resolve() == log_file_path:
            return 

    # Clean up existing file handlers before reconfiguration
    for handler in logger.handlers[:]:
        if isinstance(handler, logging.FileHandler):
            logger.removeHandler(handler)
            handler.close()

    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s.%(msecs)03d - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    try:
        log_file_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file_path, mode='a', encoding='utf-8')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        if not has_console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

        utils.set_hidden_windows(log_file_path)
    except Exception as e:
        print(f"Logging Initialization Failed: {e}")

def perform_smart_sync(source: Path, replica: Path, verify_md5: bool = True) -> dict:
    """Synchronizes source directory to replica by copying new/changed files."""
    stats = {"added": 0, "updated": 0, "removed": 0, "skipped": 0}

    if not replica.exists():
        replica.mkdir(parents=True, exist_ok=True)

    src_files = utils.get_file_list(source)

    # Comparison and copy
    for src_path in src_files:
        rel_path = src_path.relative_to(source)
        rep_path = replica / rel_path

        is_new = not rep_path.exists()
        should_copy = is_new
        
        if not should_copy:
            s_st, r_st = src_path.stat(), rep_path.stat()
            if s_st.st_size != r_st.st_size or int(s_st.st_mtime) != int(r_st.st_mtime):
                should_copy = True
            elif verify_md5:
                should_copy = utils.calculate_md5(src_path) != utils.calculate_md5(rep_path)
        
        if should_copy:
            try:
                rep_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src_path, rep_path)
                stats["added" if is_new else "updated"] += 1
            except Exception as e:
                logger.error(f"Failed to copy {src_path}: {e}")
        else:
            stats["skipped"] += 1

    # Orphaned files removal
    rep_files = utils.get_file_list(replica)
    allowed_rel_paths = {p.relative_to(source) for p in src_files}

    for rep_path in rep_files:
        rel_rep_path = rep_path.relative_to(replica)
        
        if rel_rep_path.name == utils.LOG_FILENAME:
            continue
            
        if rel_rep_path not in allowed_rel_paths:
            try:
                if rep_path.is_file() or rep_path.is_symlink():
                    rep_path.unlink(missing_ok=True)
                elif rep_path.is_dir():
                    shutil.rmtree(rep_path)
                stats["removed"] += 1
            except Exception as e:
                logger.warning(f"Could not remove orphaned item {rep_path}: {e}")

    # Recursive cleanup of empty directories
    for root, dirs, files in os.walk(replica, topdown=False):
        for name in dirs:
            dir_path = Path(root) / name
            try:
                if not os.listdir(dir_path):
                    stats["removed"] += 1
                    dir_path.rmdir()
            except:
                pass

    return stats

def perform_full_zip(source: Path, project_dest: Path, zip_name: str, password: Optional[str] = None) -> str:
    """Creates an encrypted or plain AES ZIP archive of the source directory."""
    zip_path = project_dest / zip_name
    
    try:
        files_to_zip = utils.get_file_list(source)
    except Exception as e:
        logger.error(f"Failed to scan source directory: {e}")
        raise e

    file_count = 0
    try:
        compression = pyzipper.ZIP_DEFLATED
        encryption = pyzipper.WZ_AES if password else None
        
        with pyzipper.AESZipFile(zip_path, 'w', compression=compression, encryption=encryption) as zf:
            if password: 
                zf.setpassword(password.encode('utf-8'))
            
            for file_path in files_to_zip:
                arcname = file_path.relative_to(source)
                zf.write(file_path, arcname)
                file_count += 1
                
        return f"{zip_name} ({file_count} files)"
    except Exception as e:
        logger.error(f"Backup unsuccessful. Zip creation failed: {e}")
        raise e

def run_backup_task(source_path: Path, dest_path: Path, zip_mode: bool = False, zip_filename: Optional[str] = None, 
                   password: Optional[str] = None, verify_md5: bool = True, progress_callback=None):
    """Entry point for executing backup routines based on the specified mode."""
    log_dir = dest_path if zip_mode else (dest_path / source_path.name)
    setup_logging(log_dir / utils.LOG_FILENAME)

    mode_str = " zip " if zip_mode else " "
    logger.info(f"Starting{mode_str}backup: {source_path} -> {dest_path}")
    
    try:
        if zip_mode:
            dest_path.mkdir(parents=True, exist_ok=True)
            if progress_callback: progress_callback("Compressing...")
            result = perform_full_zip(source_path, dest_path, zip_filename, password)
            logger.info(f"Zip backup successful: {result}")
            return result
        else:
            target = dest_path / source_path.name
            target.mkdir(parents=True, exist_ok=True)
            if progress_callback: progress_callback("Syncing...")
            
            s = perform_smart_sync(source_path, target, verify_md5)
            
            summary = f'Added: {s["added"]}, Updated: {s["updated"]}, Removed: {s["removed"]}, Skipped: {s["skipped"]}'
            logger.info(f"Sync Complete. {summary}")
            
            return summary
    except Exception as e:
        logger.error(f"Backup task failed: {str(e)}")
        raise e