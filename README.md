# Smart Backup Tool

A cross-platform desktop utility for secure data synchronization and archiving.

The application is built in Python using `tkinter` for the GUI and `ttkthemes` for styling. All backup operations are non-blocking, utilizing Python's `threading` module to ensure the UI remains responsive during heavy I/O tasks.

---

## Features

* **Dual Backup Modes:** Choose between two mutually exclusive methods to protect your data:
    * **Smart Sync:** Replicates the source directory. It only copies new or modified files by comparing file sizes, modification timestamps, and optional MD5 hashes.
    * **Zip Archive:** Compresses the source directory into a standalone ZIP file.
* **Advanced Archiving Options:**
    * **Versioning:** Automatically detects existing backups in the destination and increments version tags (e.g., `v1.0` to `v1.1`).
    * **Encryption:** Secures ZIP archives using AES-256 encryption.
    * **Metadata Tagging:** Optional inclusion of date stamps and custom version strings in filenames.
* **System-Level Automation:** Integrated scheduling engine that registers tasks with the host operating system:
    * **Windows:** Utilizes Task Scheduler (`schtasks`).
    * **Linux:** Utilizes `crontab`.
    * Supports Hourly, Daily, Weekly, and Monthly frequencies.
* **Full CLI Support:** Command Line Interface (`SBcli.py`) is included for headless execution, scripting, and scheduling backups.
* **Persistent Configuration:** User preferences, including directory paths, themes, and the last active tab, are saved to `.backup_config.json`.
* **Logging:** Operation logs are maintained in `.backup_operations.log` within the destination folder for audit and troubleshooting.

---

## Operation

1. **Select Paths:** Use the "Browse" buttons to set the **Source Folder** (the project to back up) and the **Backup Destination**.
2. **Choose Mode:** Select the desired workflow via the application tabs:
    * **Zip Archive:** Configure versioning, date tags, and optional AES-256 encryption.
    * **Smart Sync:** Enable MD5 content integrity verification for precise synchronization.
3. **Automate (Optional):** Set the backup frequency and click "Set Schedule" to register the task with the OS scheduler.
4. **Execute:** Click "Start Backup" to begin. The progress bar and status label will track the operation.
5. **Manage Schedules:** Use "Clear Schedule" to remove specific tasks or purge all application-registered schedules from the system.

---

## Running the Application

### Building from Source

1. **Clone the repository:**
    ```bash
    git clone https://github.com/jbacic42/SmartBackupTool
    cd smart-backup
    ```

2. **Install `tkinter` (if missing):**
    This component is often omitted in minimal Linux installations.
    * **Debian/Ubuntu:** `sudo apt-get install python3-tk`
    * **Arch Linux:** `sudo pacman -S tk`
    * **Fedora:** `sudo dnf install python3-tk`

3. **Create and activate a virtual environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

4. **Install requirements:**
    ```bash
    pip install -r requirements.txt
    ```

5. **Run the application:**
    ```bash
    python main.py
    ```

### Using the CLI
The CLI can be used for manual backups or manual scheduling:
```bash
# Perform an encrypted zip backup
python SBcli.py "/source/path" "/dest/path" -z -e "your_password"

# Schedule a daily sync with integrity check
python SBcli.py "/source/path" "/dest/path" -i -s day
