import json
import os
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import ttk
from ttkthemes import ThemedTk
import backup_core
import utils
import icons

# Global configuration and UI constants
CONFIG_FILE = utils.CONFIG_FILE
WINDOW_SIZE = "550x740"
POPUP_WIDTH = 600
POPUP_HEIGHT = 280
DEFAULT_THEME = "ubuntu"

class CustomFolderBrowser(tk.Toplevel):
    """Custom modal directory picker with integrated navigation."""
    def __init__(self, parent, title="Select Folder", initial_dir=None):
        super().__init__(parent)
        self.selected_path = None
        self.parent = parent
        self.current_path = Path(initial_dir if initial_dir else os.getcwd()).resolve()
        self.overrideredirect(True)
        self.config(highlightthickness=2.5, highlightbackground="#848899")

        # Load graphical assets
        try:
            self.icon_folder = tk.PhotoImage(data=icons.ICONS["folder"].strip())
            self.icon_lock = tk.PhotoImage(data=icons.ICONS["lock"].strip())
        except Exception:
            self.icon_folder = None
            self.icon_lock = None

        self.width = POPUP_WIDTH
        self.height = 400

        center_to_parent(self)
        self.bind_id = self.parent.bind("<Configure>", lambda e: center_to_parent(self))
        
        self.title(title)
        self.resizable(False, False)
        self.transient(self.parent)

        # UI Construction
        top_frame = ttk.Frame(self, padding=(20, 5, 20, 0))
        top_frame.pack(fill=tk.X)

        self.close_btn = ttk.Button(top_frame, text="✕", cursor="hand2", command=self.cleanup_and_destroy, width=3)
        self.close_btn.place(relx=1.0, rely=0.0, anchor="ne", x=12)
        
        ttk.Button(top_frame, text="⬆ Up", command=self.go_up, width=6).pack(side=tk.LEFT)

        self.lbl_path = ttk.Label(top_frame, text=str(self.current_path), anchor="w", relief="sunken")
        self.lbl_path.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 80))

        list_frame = ttk.Frame(self, padding=(10, 0, 10, 0))
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        self.tree = ttk.Treeview(list_frame, columns=("path"), show="tree", selectmode="browse")
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.bind("<Double-1>", self.on_double_click)
        self.tree.bind("<Button-1>", self.check_empty_click)

        btn_frame = ttk.Frame(self, padding=10)
        btn_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        ttk.Button(btn_frame, text="Cancel", command=self.cleanup_and_destroy).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Select Folder", command=self.on_select).pack(side=tk.RIGHT, padx=5)

        self.refresh_list()
        self.wait_window(self)

    def refresh_list(self):
        """Populates treeview with subdirectories of the current path."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.lbl_path.config(text=str(self.current_path))
        try:
            for item in sorted(self.current_path.iterdir()):
                if item.is_dir() and not item.name.startswith('.'):
                    icon = self.icon_folder if self.icon_folder else ""
                    self.tree.insert("", "end", text=f" {item.name}", image=icon, values=(str(item),))
        except PermissionError:
             icon = self.icon_lock if self.icon_lock else ""
             self.tree.insert("", "end", text=" Access Denied", image=icon)
        except Exception as e:
            self.tree.insert("", "end", text=f" Error: {e}")

    def go_up(self):
        """Navigates to the parent directory."""
        parent = self.current_path.parent
        if parent != self.current_path:
            self.current_path = parent
            self.refresh_list()

    def check_empty_click(self, event):
        """Deselcts items if clicking empty space in the treeview."""
        if not self.tree.identify_row(event.y):
            self.tree.selection_remove(self.tree.selection())

    def on_double_click(self, event):
        """Handles directory traversal via double-click."""
        item_id = self.tree.focus()
        if item_id:
            values = self.tree.item(item_id, "values")
            if values:
                self.current_path = Path(values[0])
                self.refresh_list()

    def on_select(self):
        """Confirms selection and closes the dialog."""
        selected_items = self.tree.selection()
        if selected_items:
            item_id = selected_items[0]
            values = self.tree.item(item_id, "values")
            if values:
                self.selected_path = values[0]
                self.cleanup_and_destroy()
                return
        self.selected_path = str(self.current_path)
        self.cleanup_and_destroy()

    def cleanup_and_destroy(self):
        """Unbinds parent events and destroys the widget."""
        if hasattr(self, 'bind_id'):
            self.parent.unbind("<Configure>", self.bind_id)
        self.destroy()

class WideMessageDialog(tk.Toplevel):
    """Generic message dialog with support for errors, confirmations, and custom icons."""
    def __init__(self, parent, title, message, is_error=False, is_confirm=False, btn_txt=None):
        super().__init__(parent)
        self.parent = parent
        self.result = None 
        
        self.overrideredirect(True)
        self.config(highlightthickness=2.5, highlightbackground="#848899")

        self.width = POPUP_WIDTH
        self.height = POPUP_HEIGHT

        center_to_parent(self)
        self.bind_id = self.parent.bind("<Configure>", lambda e: center_to_parent(self))
        
        self.title(title)
        self.resizable(False, False)
        self.transient(self.parent)

        frame = ttk.Frame(self, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        self.close_btn = ttk.Button(frame, text="✕", cursor="hand2", command=self.on_close, width=3)
        self.close_btn.place(relx=1.0, rely=0.0, anchor="ne", x=12, y=-17)

        self.icon_img = None
        try:
            if is_error:
                self.icon_img = tk.PhotoImage(data=icons.ICONS["error"].strip())
            elif is_confirm:
                self.icon_img = tk.PhotoImage(data=icons.ICONS["question"].strip())
            elif title == "Success":
                self.icon_img = tk.PhotoImage(data=icons.ICONS["success"].strip())
            else:
                self.icon_img = tk.PhotoImage(data=icons.ICONS["info"].strip())
        except Exception:
            pass

        content_frame = ttk.Frame(frame)
        content_frame.pack(expand=True) 
        
        if self.icon_img:
            ttk.Label(content_frame, image=self.icon_img).pack(side=tk.LEFT, padx=(0, 15))
            
        ttk.Label(content_frame, text=message, wraplength=self.width-150, justify="left").pack(side=tk.LEFT)
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(20, 0))
        
        if btn_txt:
            lBut, rBut = btn_txt.split("/")
        else:
            lBut, rBut = "Yes", "No"

        if is_confirm:
            ttk.Button(btn_frame, text=lBut, command=self.on_yes).pack(side=tk.LEFT, expand=True, padx=5)
            ttk.Button(btn_frame, text=rBut, command=self.on_no).pack(side=tk.LEFT, expand=True, padx=5)
        else:
            ttk.Button(btn_frame, text="OK", command=self.on_ok).pack(expand=True)
            
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.wait_window(self)

    def cleanup_and_destroy(self):
        if hasattr(self, 'bind_id'):
            self.parent.unbind("<Configure>", self.bind_id)
        self.destroy()

    def on_ok(self): 
        self.result = True
        self.cleanup_and_destroy()

    def on_yes(self): 
        self.result = True
        self.cleanup_and_destroy()

    def on_no(self): 
        self.result = False
        self.cleanup_and_destroy()

    def on_close(self): 
        self.result = None
        self.cleanup_and_destroy()

def center_to_parent(popup):
    """Dynamically centers a popup window relative to its parent's geometry."""
    x = popup.parent.winfo_x() + (popup.parent.winfo_width() // 2) - (popup.width // 2)
    y = popup.parent.winfo_y() + (popup.parent.winfo_height() // 2) - (popup.height // 2)
    popup.geometry(f"{popup.width}x{popup.height}+{x}+{y}")

class SmartBackupApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Smart Backup Tool")
        self.root.geometry(WINDOW_SIZE)
        self.root.resizable(False, False)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.config = self.load_config()
        self.root.set_theme(self.config.get("theme", DEFAULT_THEME))
        self._fix_treeview_style()

        # Observable UI states
        self.source_var = tk.StringVar(value=self.config.get("last_source", ""))
        self.dest_var = tk.StringVar(value=self.config.get("last_dest", ""))
        self.encrypt_var = tk.BooleanVar(value=self.config.get("encrypt", False))
        self.password_var = tk.StringVar()
        self.md5_var = tk.BooleanVar(value=self.config.get("verify_integrity", True))
        self.status_var = tk.StringVar(value="Ready")
        self.use_date_var = tk.BooleanVar(value=self.config.get("use_date", False))
        self.auto_ver_var = tk.BooleanVar(value=self.config.get("auto_version", False))
        self.use_version_var = tk.BooleanVar(value=self.config.get("use_version_tag", True))
        self.version_var = tk.StringVar(value="v1.0")
        self.detected_max_version = None

        self._build_ui()
        last_tab = self.config.get("last_tab_index", 0)
        try:
            self.tabs.select(last_tab)
        except Exception:
            self.tabs.select(0)
            
        self.check_destination_version()
        self.toggle_encryption()
        self.toggle_version_usage()
        self.last_initialized_log = None

    def on_close(self):
        """Interprets exit request; validates state of active background threads."""
        if hasattr(self, 'backup_thread') and self.backup_thread.is_alive():
            confirm = WideMessageDialog(
                self.root, 
                "Backup in Progress", 
                "A backup is currently running. Closing now may result in corrupted data.\n\nAre you sure you want to exit?", 
                is_confirm=True
            )
            if not confirm.result:
                return 

        self.root.destroy()
        sys.exit(0)

    def _fix_treeview_style(self):
        style = ttk.Style()
        style.map("Treeview", background=[('selected', '#3498db')], foreground=[('selected', 'white')])

    def _build_ui(self):
        """Initializes the primary application interface layout."""
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        self.entry_src = self._create_file_selector(main_frame, "Source Folder (Project):", self.source_var, self.browse_source)
        self.entry_dest = self._create_file_selector(main_frame, "Backup Destination:", self.dest_var, self.browse_dest, pady=(10, 0))

        self.tabs = ttk.Notebook(main_frame)
        self.tabs.pack(fill=tk.BOTH, expand=True, pady=20)

        # Archive Tab
        self.tab_zip = ttk.Frame(self.tabs, padding=15)
        self.tabs.add(self.tab_zip, text="Zip Archive")
        
        row_v_toggle = ttk.Frame(self.tab_zip)
        row_v_toggle.pack(fill=tk.X, pady=(0, 5))
        self.chk_use_version = ttk.Checkbutton(row_v_toggle, text="Use Version Tag", variable=self.use_version_var, command=self.toggle_version_usage)
        self.chk_use_version.pack(side=tk.LEFT)
        ttk.Checkbutton(row_v_toggle, text="Use Date Tag", variable=self.use_date_var).pack(side=tk.LEFT, padx=(20, 0))

        self.row_v_controls = ttk.Frame(self.tab_zip)
        self.row_v_controls.pack(fill=tk.X, pady=(0, 15)) 
        self.entry_version = ttk.Entry(self.row_v_controls, textvariable=self.version_var, width=15)
        self.entry_version.pack(side=tk.LEFT, padx=(20, 10)) 
        self.chk_auto = ttk.Checkbutton(self.row_v_controls, text="Auto-increment", variable=self.auto_ver_var, command=self.toggle_auto_version)
        self.chk_auto.pack(side=tk.LEFT)
        self.btn_scan = ttk.Button(self.row_v_controls, text="Scan", width=6, command=self.scan_for_latest_version)
        self.btn_scan.pack(side=tk.LEFT, padx=10)

        row_enc = ttk.Frame(self.tab_zip)
        row_enc.pack(fill=tk.X, pady=(0, 5))
        ttk.Checkbutton(row_enc, text="Encrypt (AES-256)", variable=self.encrypt_var, command=self.toggle_encryption).pack(side=tk.LEFT)
        
        row_pwd = ttk.Frame(self.tab_zip)
        row_pwd.pack(fill=tk.X)
        ttk.Label(row_pwd, text="Password:").pack(side=tk.LEFT)
        self.entry_password = ttk.Entry(row_pwd, textvariable=self.password_var, width=25, show="*")
        self.entry_password.pack(side=tk.LEFT, padx=10)
        
        # Synchronization Tab
        self.tab_sync = ttk.Frame(self.tabs, padding=15)
        self.tabs.add(self.tab_sync, text="Smart Sync")
        ttk.Label(self.tab_sync, text="Synchronize source folder to destination.").pack(anchor="w", pady=(0, 10))
        ttk.Checkbutton(self.tab_sync, text="Verify content integrity (MD5 hash)", variable=self.md5_var).pack(anchor="w")
        ttk.Label(self.tab_sync, text="If unchecked files are compared using only size \nand modification time.", foreground="gray").pack(anchor="w", padx=20)

        # Automation frame
        sched_frame = ttk.LabelFrame(main_frame, text="Automation", padding=10)
        sched_frame.pack(fill=tk.X, pady=(10, 0))
        ttk.Label(sched_frame, text="Frequency:").pack(side=tk.LEFT)
        self.combo_freq = ttk.Combobox(sched_frame, values=["Hour", "Day", "Week", "Month"], state="readonly", width=10)
        self.combo_freq.set("Day")
        self.combo_freq.pack(side=tk.LEFT, padx=10)
        ttk.Button(sched_frame, text="Set Schedule", command=self.handle_schedule_click).pack(side=tk.RIGHT)
        
        bottom_row = ttk.Frame(main_frame)
        bottom_row.pack(fill=tk.X, pady=10)

        theme_frame = ttk.Frame(bottom_row)
        theme_frame.pack(side=tk.LEFT)
        ttk.Label(theme_frame, text="Theme:").pack(side=tk.LEFT)
        self.theme_combo = ttk.Combobox(theme_frame, values=sorted(self.root.get_themes()), state="readonly")
        self.theme_combo.set(self.root.current_theme)
        self.theme_combo.pack(side=tk.LEFT, padx=10)
        self.theme_combo.bind("<<ComboboxSelected>>", self.change_theme)

        ttk.Button(bottom_row, text="Clear Schedule", command=self.handle_clear_schedule).pack(side=tk.RIGHT)

        self.progress = ttk.Progressbar(main_frame, mode="indeterminate")
        self.progress.pack(fill=tk.X, pady=(20, 5))
        ttk.Label(main_frame, textvariable=self.status_var, foreground="gray").pack()

        self.btn_backup = ttk.Button(main_frame, text="Start Backup", command=self.start_backup_thread)
        self.btn_backup.pack(pady=10, fill=tk.X)

    def _create_file_selector(self, parent, label_text, variable, command, pady=5):
        """Helper to construct labeled entry fields with browse buttons."""
        ttk.Label(parent, text=label_text).pack(anchor="w", pady=pady)
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.X, pady=5)
        entry = ttk.Entry(frame, textvariable=variable)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        entry.bind("<FocusOut>", lambda e: self.check_destination_version())
        ttk.Button(frame, text="Browse", command=command).pack(side=tk.RIGHT, padx=5)
        return entry

    def browse_source(self):
        d = CustomFolderBrowser(self.root, title="Select Source", initial_dir=self.source_var.get())
        if d.selected_path: self.source_var.set(d.selected_path); self.check_destination_version()

    def browse_dest(self):
        d = CustomFolderBrowser(self.root, title="Select Destination", initial_dir=self.dest_var.get())
        if d.selected_path: self.dest_var.set(d.selected_path); self.check_destination_version()

    def check_destination_version(self):
        """Queries the filesystem to identify existing version history."""
        src = Path(self.source_var.get().strip()) if self.source_var.get() else None
        dest = Path(self.dest_var.get().strip()) if self.dest_var.get() else None
        self.detected_max_version = utils.get_latest_version_in_folder(src, dest)
        self.refresh_version_display()

    def refresh_version_display(self):
        """Updates the version string based on current scan results and auto-increment settings."""
        if self.detected_max_version and self.use_version_var.get() and self.auto_ver_var.get():
            self.version_var.set(utils.increment_version_string(self.detected_max_version))
        elif not self.detected_max_version and self.use_version_var.get() and self.auto_ver_var.get():
            self.version_var.set("v1.0")

    def scan_for_latest_version(self):
        """Invokes version detection and provides user feedback via dialog."""
        self.check_destination_version()
        if self.detected_max_version:
            nxt = utils.increment_version_string(self.detected_max_version)
            msg = f"Latest backup: {self.detected_max_version}\n\n" + (f"Next set to: {nxt}" if self.auto_ver_var.get() else f"Auto-increment starts with: {nxt}")
            WideMessageDialog(self.root, "Scan Complete", msg)
        else:
            WideMessageDialog(self.root, "Scan Result", "No identifiable versions found. v1.0 set as next.")

    def handle_schedule_click(self):
        """Configures background task automation based on UI settings."""
        if not utils.verify_cli_exists():
            WideMessageDialog(self.root, "Missing Component", "CLI component not found.", is_error=True)
            return

        src = self.source_var.get().strip()
        dst = self.dest_var.get().strip()
        path_error = utils.validate_backup_paths(src, dst)
        
        if path_error:
            WideMessageDialog(self.root, "Error", path_error, is_error=True)
            return

        prompt = WideMessageDialog(
            self.root, 
            "Schedule Options", 
            "Would you like to run the backup immediately as well as scheduling it?", 
            is_confirm=True, 
            btn_txt="Run Now & Schedule/Schedule Only"
        )

        if prompt.result is None: return

        run_now = prompt.result
        is_zip = (self.tabs.index("current") == 0)
        
        if run_now and is_zip:
            v_tag = self.version_var.get().strip() if self.use_version_var.get() else ""
            z_name = utils.generate_backup_filename(Path(src), v_tag, self.use_date_var.get())
            
            if (Path(dst) / z_name).exists():
                confirm = WideMessageDialog(self.root, "Confirm Overwrite", f"The file '{z_name}' already exists. Overwrite?", is_confirm=True)
                if not confirm.result: return

        # Command flag construction
        flags = "-i" if (not is_zip and self.md5_var.get()) else ""
        if is_zip:
            flags += "-z"
            if self.use_date_var.get(): flags += " -d"
            if self.use_version_var.get():
                v_val = self.version_var.get().strip()
                if self.auto_ver_var.get(): flags += " -v auto"
                elif not v_val:
                    WideMessageDialog(self.root, "Error", "Version tag required."); return
                else: flags += f' -v "{v_val}"'

            if self.encrypt_var.get():
                pwd = self.password_var.get().strip()
                if not pwd:
                    WideMessageDialog(self.root, "Error", "Encryption requires a password.", is_error=True); return
                flags += f' -ep "{utils.encrypt_password(pwd)}"'

        interval = self.combo_freq.get().lower()
        full_command_args = f'"{src}" "{dst}" {flags}'.strip()

        self.save_config()
        if utils.add_to_scheduler(interval, full_command_args, src, dst, run_now, is_zip):
            WideMessageDialog(self.root, "Success", "Task scheduled successfully.")
            if run_now and is_zip: self.check_destination_version()
        else:
            WideMessageDialog(self.root, "Error", "Failed to register task.", is_error=True)

    def handle_clear_schedule(self):
        """Orchestrates the removal of one or all scheduled tasks."""
        src = self.source_var.get().strip()
        dst = self.dest_var.get().strip()

        scope_dlg = WideMessageDialog(self.root, "Select Scope", "Select task clearing scope:", is_confirm=True, btn_txt="Clear this task/Clear all tasks")
        if scope_dlg.result is None: return

        if scope_dlg.result is True:
            final = WideMessageDialog(self.root, "Confirm Cancellation", f"Stop schedule for:\nSRC: {src}\nDST: {dst}?", is_confirm=True)
            if final.result is True:
                if utils.remove_specific_schedule(src, dst):
                    WideMessageDialog(self.root, "Success", "Scheduled task removed.")
                else:
                    WideMessageDialog(self.root, "Not found", "Scheduled task not found.")
        elif scope_dlg.result is False:
            final = WideMessageDialog(self.root, "Confirm Clear All", "Clear ALL scheduled backups? This cannot be undone.", is_confirm=True, is_error=True)
            if final.result is True:
                if utils.remove_all_schedules():
                    WideMessageDialog(self.root, "Success", "All scheduled tasks cleared.")
                else:
                    WideMessageDialog(self.root, "Not found", "No active tasks found.")

    def start_backup_thread(self):
        """Initializes logging and spawns the backup execution thread."""
        src_str = self.source_var.get().strip()
        dest_str = self.dest_var.get().strip()
        error = utils.validate_backup_paths(src_str, dest_str)
        
        if error:
            WideMessageDialog(self.root, "Error", error, is_error=True); return

        src_path, dest_path = Path(src_str), Path(dest_str)
        is_zip = (self.tabs.index("current") == 0)

        if is_zip and self.encrypt_var.get() and not self.password_var.get():
            WideMessageDialog(self.root, "Error", "Password required for encryption.", is_error=True); return

        v_tag = self.version_var.get().strip() if self.use_version_var.get() else ""
        z_name = utils.generate_backup_filename(src_path, v_tag, self.use_date_var.get())

        if is_zip and (dest_path / z_name).exists():
            confirm = WideMessageDialog(self.root, "Confirm Overwrite", f"Overwrite existing file '{z_name}'?", is_confirm=True)
            if not confirm.result: return

        self.save_config()
        self.btn_backup.config(state="disabled")
        self.progress.start(10)
        
        pwd = self.password_var.get() if self.encrypt_var.get() else None
        self.backup_thread = threading.Thread(
            target=self.run_backup, 
            args=(is_zip, z_name, src_path, dest_path, pwd), 
            daemon=True
        )
        self.backup_thread.start()

    def run_backup(self, is_zip, zip_name, src_path, dest_path, password):
        """Worker function for non-blocking backup operations."""
        try:
            res = backup_core.run_backup_task(
                source_path=src_path,
                dest_path=dest_path,
                zip_mode=is_zip,
                zip_filename=zip_name,
                password=password,
                verify_md5=self.md5_var.get(),
                progress_callback=lambda m: self.root.after(0, lambda: self.status_var.set(m))
            )
            self.root.after(0, lambda: self.finish_success(res))
        except Exception as e:
            self.root.after(0, lambda: self.finish_error(str(e)))

    def finish_success(self, msg):
        """Restores UI state after successful task completion."""
        self.progress.stop(); self.btn_backup.config(state="normal")
        self.status_var.set("Success!"); self.check_destination_version()
        WideMessageDialog(self.root, "Success", f'Sync Complete\n{msg}')

    def finish_error(self, err):
        """Restores UI state and reports errors after task failure."""
        self.progress.stop(); self.btn_backup.config(state="normal")
        WideMessageDialog(self.root, "Backup Failed", err, is_error=True)

    def toggle_version_usage(self):
        state = 'normal' if self.use_version_var.get() else 'disabled'
        self.chk_auto.config(state=state); self.btn_scan.config(state=state)
        if state == 'normal': self.toggle_auto_version()
        else: self.entry_version.config(state='disabled')

    def toggle_auto_version(self):
        if self.auto_ver_var.get(): self.entry_version.config(state='disabled'); self.check_destination_version()
        else: self.entry_version.config(state='normal')

    def toggle_encryption(self): self.entry_password.config(state='normal' if self.encrypt_var.get() else 'disabled')

    def change_theme(self, e): self.root.set_theme(self.theme_combo.get()); self._fix_treeview_style()
    
    def load_config(self):
        """Deserializes application state from local JSON storage."""
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, "r") as f: return json.load(f)
            except Exception: return {}
        return {}

    def save_config(self):
        """Serializes current UI settings to local JSON storage."""
        cfg = {
            "last_source": self.source_var.get(), "last_dest": self.dest_var.get(),
            "verify_integrity": self.md5_var.get(), "use_zip": (self.tabs.index("current") == 0),
            "use_date": self.use_date_var.get(), "auto_version": self.auto_ver_var.get(),
            "use_version_tag": self.use_version_var.get(), "encrypt": self.encrypt_var.get(),
            "theme": self.theme_combo.get(), "last_tab_index": self.tabs.index("current")
        }
        with open(CONFIG_FILE, "w") as f: json.dump(cfg, f, indent=4)
        utils.set_hidden_windows(CONFIG_FILE)

if __name__ == "__main__":
    root_window = ThemedTk()
    try:
        app = SmartBackupApp(root_window)
        root_window.mainloop()
    except Exception as e:
        print(f"Failed to launch GUI: {e}")
        sys.exit(1)