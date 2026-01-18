import argparse
import sys
from pathlib import Path
import utils
import backup_core

def run_cli():
    """Entry point for the Smart Backup command-line interface."""
    parser = argparse.ArgumentParser(description="Smart Backup CLI")
    
    # Path arguments: nargs='*' supports global commands without path requirements
    parser.add_argument("paths", nargs='*', help="Source and Destination directories")
    
    # Operation and configuration flags
    parser.add_argument("-z", "--zip", action="store_true", help="Use Zip mode")
    parser.add_argument("-i", "--integrity", action="store_true", help="Verify MD5 (Sync mode only)")
    parser.add_argument("-d", "--date", action="store_true", help="Include date tag in filename")
    parser.add_argument("-s", "--schedule", choices=['hour', 'day', 'week', 'month', 'clear', 'clr'], 
                        help="Schedule frequency or global cleanup")
    parser.add_argument("-c", "--clear", action="store_true", help="Clear specific task for provided src/dst")
    parser.add_argument("-v", "--version", help="Version tag (e.g., v1.0)")

    # Mutually exclusive password handling
    pgroup = parser.add_mutually_exclusive_group()
    pgroup.add_argument("-e", "--encrypt", metavar="PASSWORD", help="Plaintext password")
    pgroup.add_argument("-ep", "--enc_pass", metavar="ENC_PASSWORD", help="Encoded password")

    args = parser.parse_args()

    # Global scheduler cleanup logic
    if args.schedule in ['clear', 'clr']:
        confirm = input("Are you sure you want to remove ALL SmartBackup tasks? (y/N): ").lower().strip()
        if confirm == 'y':
            if utils.remove_all_schedules():
                print("All SmartBackup tasks were deleted from the scheduler.")
                sys.exit(0)
            else:
                print("No scheduled tasks were found.")
                sys.exit(1)
        else:
            print("Operation aborted.")
            sys.exit(0)

    # Positional path validation for execution and specific cleanup
    if len(args.paths) < 2:
        print(f"Error: Source and Destination paths are required.")
        print(f"Usage: python {utils.CLI_BASE_NAME}.py <src> <dst> [flags]")
        print(f"To clear all tasks: python {utils.CLI_BASE_NAME}.py -s clear")
        sys.exit(1)

    src_path = Path(args.paths[0]).resolve()
    dest_path = Path(args.paths[1]).resolve()

    # Individual task removal logic
    if args.clear:
        if utils.remove_specific_schedule(str(src_path), str(dest_path)):
            print(f"Scheduled task: {src_path} -> {dest_path}\nDeleted successfully.")
            sys.exit(0)
        else:
            print(f"Scheduled task ({src_path} -> {dest_path}) not found.")
            sys.exit(1)

    # Validation for mode-specific arguments
    if args.zip:
        if args.integrity:
            parser.error("-i is only for Sync mode. -z and -i cannot be used together.")
    else:
        if args.date or args.version or args.encrypt or args.enc_pass:
            parser.error("Zip flags (-d, -v, -e, -ep) require -z.")
    
    # Credential processing
    password = None
    if args.enc_pass:
        try:
            password = utils.decrypt_password(args.enc_pass)
        except Exception:
            print(f"Password decryption failed. Use -e for plaintext.")
            return
    elif args.encrypt:
        password = args.encrypt

    # Logging initialization
    backup_core.setup_logging(dest_path / utils.LOG_FILENAME)

    # Task automation registration
    if args.schedule:
        run_now = False
        if sys.stdout.isatty():
            try:
                choice = input("Run backup immediately too? (y/N): ").lower().strip()
                run_now = choice == 'y'
            except (EOFError, KeyboardInterrupt):
                sys.exit(1)

        is_zip = bool(args.zip)
        flags = "-z " if is_zip else ""
        if args.integrity: flags += "-i "
        if args.date: flags += "-d "
        if args.version: flags += f'-v "{args.version}" '
        if password:
            flags += f'-ep "{utils.encrypt_password(password)}"'

        full_cmd_args = f'"{src_path}" "{dest_path}" {flags.strip()}'
        success = utils.add_to_scheduler(args.schedule, full_cmd_args, str(src_path), str(dest_path), run_now, is_zip)
        
        if success:
            print(f"Scheduled backup (Every {args.schedule}): {src_path} -> {dest_path}")
        sys.exit(0 if success else 1)

    # Single-run execution logic
    z_mode = False
    z_name = None
    if args.zip:
        z_mode = True
        v_tag = args.version or ""
        if v_tag.lower() in ['auto', 'a']:
            latest = utils.get_latest_version_in_folder(src_path, dest_path)
            v_tag = utils.increment_version_string(latest) if latest else "v1.0"
        z_name = utils.generate_backup_filename(src_path, v_tag, args.date)

    try:
        res = backup_core.run_backup_task(
            source_path=src_path,
            dest_path=dest_path,
            zip_mode=z_mode,
            zip_filename=z_name,
            password=password,
            verify_md5=args.integrity,
            progress_callback=lambda m: print(f" > {m}")
        )
        print(f"\nTask Complete: {res}")
    except Exception as e:
        print(f"\nCritical Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    run_cli()