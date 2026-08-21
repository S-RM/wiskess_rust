import tkinter as tk
import webbrowser
import pathlib
import os
import sys
import logging
import time
import subprocess
import platform

import helpers

from tkinter import ttk
from tkinter import filedialog, messagebox

from config_manager import ConfigManager

# --- Logger Setup ---
logger = logging.getLogger(f"srum_dump.{__name__}")
# --- End Logger Setup ---

# Determine base path for resources
if getattr(sys, 'frozen', False):
    base_path = sys._MEIPASS
    logger.debug(f"Running frozen, base_path: {base_path}")
else:
    base_path = os.path.abspath(".")
    logger.debug(f"Running as script, base_path: {base_path}")

icon_path = os.path.join(base_path, 'srum_dump.ico')
logger.debug(f"Icon path: {icon_path}")


def open_file_with_default_app(file_path):
    """Opens a file with the default application for the platform."""
    logger.debug(f"Opening file with default app: {file_path}")
    try:
        system = platform.system()
        if system == 'Windows':
            os.startfile(file_path)
        elif system == 'Darwin':  # macOS
            subprocess.run(['open', file_path], check=True)
        elif system == 'Linux': 
            subprocess.run(['xdg-open', file_path], check=True)
        else:
            logger.warning(f"Unknown platform: {system}. Cannot open file.")
            raise NotImplementedError(f"File opening not supported on {system}")
        logger.info(f"Successfully opened file: {file_path}")
    except Exception as e:
        logger.exception(f"Error opening file: {e}")
        raise


class ProgressWindow: 
    def __init__(self, title="SRUM Dump Progress"):
        logger.debug(f"Initializing ProgressWindow with title:  {title}")
        try:
            self.root = tk.Tk()
            self.root.title(title)
            self.root.geometry("600x400")
            self.root. after(2000, self.remove_topmost, self.root)
            try:
                self.root.iconbitmap(icon_path)
            except tk.TclError:
                logger.exception("Icon file not found or invalid.")

            # Current table label
            self.table_label = tk.Label(self.root, text="Preparing to dump tables .. .", font=('Arial', 10))
            self.table_label. pack(pady=5)

            # Progress bar frame
            progress_frame = tk.Frame(self.root)
            progress_frame.pack(fill=tk.X, padx=20, pady=5)

            self.progress_var = tk.DoubleVar()
            self.progress_bar = ttk.Progressbar(
                progress_frame,
                variable=self.progress_var,
                maximum=100
            )
            self.progress_bar.pack(fill=tk.X)

            # Stats frame
            stats_frame = tk.Frame(self.root)
            stats_frame.pack(fill=tk.X, padx=20, pady=5)

            # Records dumped
            self.records_var = tk.StringVar(value="Records Dumped: 0")
            self.records_label = tk.Label(stats_frame, textvariable=self.records_var)
            self.records_label. pack(side=tk.LEFT, padx=10)

            # Records per second
            self.rps_var = tk.StringVar(value="Records/sec: 0")
            self.rps_label = tk.Label(stats_frame, textvariable=self.rps_var)
            self.rps_label.pack(side=tk. RIGHT, padx=10)

            # Log text area
            log_frame = tk.Frame(self.root)
            log_frame.pack(fill=tk. BOTH, expand=True, padx=20, pady=5)

            # Scrollbar
            scrollbar = tk.Scrollbar(log_frame)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

            # Text widget
            self.log_text = tk.Text(log_frame, height=15, wrap=tk.WORD, yscrollcommand=scrollbar.set)
            self.log_text.pack(fill=tk.BOTH, expand=True)
            scrollbar.config(command=self.log_text.yview)

            # Close button frame
            button_frame = tk.Frame(self.root)
            button_frame.pack(fill=tk.X, padx=20, pady=5)

            # Close button - initially disabled
            self.close_button = tk.Button(
                button_frame,
                text="Close",
                command=self.close,
                state=tk.DISABLED
            )
            self.close_button.pack(side=tk.RIGHT)

            self.total_tables = 0
            self.current_table = 0
            logger.debug("ProgressWindow initialized successfully.")
        except Exception as e:
            logger.exception(f"Error during ProgressWindow initialization: {e}")

    def start(self, total_tables):
        """Initialize the progress window with total number of tables"""
        logger.debug(f"Starting ProgressWindow with total_tables: {total_tables}")
        try:
            self.total_tables = total_tables
            self. current_table = 0
            self.progress_var.set(0)
            self.update()
            logger.debug("ProgressWindow started.")
        except Exception as e: 
            logger.exception(f"Error in ProgressWindow start method: {e}")

    def remove_topmost(self, window):
        logger.debug("Called remove_topmost")
        try:
            if window and window.winfo_exists():
                window.attributes('-topmost', False)
                logger.debug("Removed topmost attribute.")
            else:
                logger.warning("Window does not exist in remove_topmost.")
        except Exception as e:
            logger. exception(f"Error removing topmost attribute: {e}")

    def set_current_table(self, table_name):
        """Update the current table being processed"""
        logger.debug(f"Setting current table to: {table_name}")
        try:
            self.current_table += 1
            self.table_label.config(text=f"Current Task: {table_name}")
            if self.total_tables > 0:
                progress_percent = (self.current_table / self.total_tables) * 100
                self.progress_var.set(progress_percent)
                logger.debug(f"Progress set to {progress_percent:.2f}%")
            else:
                logger.warning("Total tables is 0, cannot calculate progress percentage.")
            self.update()
        except Exception as e:
            logger.exception(f"Error in set_current_table: {e}")

    def update_stats(self, records_dumped, records_per_second):
        """Update the statistics display"""
        logger.debug(f"Updating stats: records_dumped={records_dumped}, records_per_second={records_per_second}")
        try:
            self.records_var. set(f"Records Dumped: {records_dumped:,}")
            self.rps_var.set(f"Records/sec: {records_per_second:.1f}")
            self.update()
        except Exception as e: 
            logger.exception(f"Error in update_stats: {e}")

    def log_message(self, message):
        """Add a message to the log window"""
        logger.debug(f"Called log_message (message length: {len(message)})")
        try:
            if self.log_text.winfo_exists():
                self.log_text.insert(tk.END, f"{message}\n")
                self.log_text.see(tk.END)
                self.update()
            else:
                logger.warning("Log text widget does not exist in log_message.")
        except Exception as e:
            logger.exception(f"Error in log_message: {e}")

    def update(self):
        """Force window update"""
        logger.debug("Called update")
        try:
            if self.root and self.root.winfo_exists():
                self.root.update_idletasks()
                self.root.update()
                logger.debug("Window updated.")
            else:
                logger.warning("Root window does not exist in update.")
        except Exception as e:
            logger.warning(f"Error during UI update (might be expected during close): {e}")

    def hide_record_stats(self):
        """Hide the records stats labels"""
        logger.debug("Called hide_record_stats")
        try:
            if self.records_label. winfo_exists():
                self.records_label.pack_forget()
            if self.rps_label. winfo_exists():
                self.rps_label.pack_forget()
            logger.debug("Record stats hidden.")
        except Exception as e:
            logger.exception(f"Error in hide_record_stats:  {e}")

    def finished(self):
        """Enable the close button when processing is complete"""
        logger.debug("Called finished")
        try:
            if self.close_button.winfo_exists():
                self.close_button.config(state=tk.NORMAL)
                self.close_button.bind("<Enter>", lambda e: self.close_button.config(bg="#e0e0e0"))
                self.close_button.bind("<Leave>", lambda e: self.close_button.config(bg="#f0f0f0"))
                logger.debug("Close button enabled.")
            else:
                logger. warning("Close button does not exist in finished.")
        except Exception as e:
            logger.exception(f"Error in finished method: {e}")

    def close(self):
        """Close the progress window"""
        logger.debug("Called close")
        try:
            if self.root and self.root.winfo_exists():
                self.root.destroy()
                logger.info("ProgressWindow closed.")
            else:
                logger.warning("Root window does not exist or already destroyed in close.")
        except Exception as e:
            logger.exception(f"Error closing ProgressWindow: {e}")


def error_message_box(title, message):
    logger.debug(f"Called error_message_box with title: {title}, message: {message[: 50]}...")
    try:
        messagebox.showerror(title, message)
        logger.info(f"Displayed error message box with title: {title}")
    except Exception as e: 
        logger.exception(f"Error displaying error message box: {e}")


def message_box(title, message):
    logger.debug(f"Called message_box with title: {title}, message: {message[:50]}...")
    try:
        messagebox.showinfo(title, message)
        logger.info(f"Displayed info message box with title: {title}")
    except Exception as e: 
        logger.exception(f"Error displaying info message box: {e}")


def browse_file(initial_dir, filetypes):
    logger.debug(f"Called browse_file with initial_dir: {initial_dir}, filetypes: {filetypes}")
    file_path = ""
    root = None
    try:
        root = tk. Tk()
        root.withdraw()
        logger.debug("Temporary Tk root created and withdrawn.")
        resolved_initial_dir = str(pathlib.Path(initial_dir).resolve())
        logger.debug(f"Resolved initial directory: {resolved_initial_dir}")
        file_path = filedialog.askopenfilename(initialdir=resolved_initial_dir, filetypes=filetypes)
        logger.info(f"File dialog returned: {file_path}")
        if file_path:
            canonical_path = str(pathlib.Path(file_path).resolve())
            logger. debug(f"Canonicalized path: {canonical_path}")
            return canonical_path
        else: 
            logger.debug("No file selected.")
            return ""
    except Exception as e: 
        logger.exception(f"Error in browse_file: {e}")
        return ""
    finally: 
        if root:
            try:
                root.destroy()
                logger.debug("Temporary Tk root destroyed.")
            except Exception as destroy_e:
                logger.warning(f"Error destroying temporary Tk root in browse_file: {destroy_e}")


def browse_directory(initial_dir):
    logger.debug(f"Called browse_directory with initial_dir: {initial_dir}")
    directory_path = ""
    root = None
    try:
        root = tk.Tk()
        root.withdraw()
        logger.debug("Temporary Tk root created and withdrawn.")
        resolved_initial_dir = str(pathlib. Path(initial_dir).resolve())
        logger.debug(f"Resolved initial directory: {resolved_initial_dir}")
        directory_path = filedialog.askdirectory(initialdir=resolved_initial_dir)
        logger.info(f"Directory dialog returned:  {directory_path}")
        if directory_path:
            resolved_path = str(pathlib.Path(directory_path).resolve())
            logger.debug(f"Resolved directory path: {resolved_path}")
            return resolved_path
        else:
            logger.debug("No directory selected.")
            return ""
    except Exception as e:
        logger.exception(f"Error in browse_directory: {e}")
        return ""
    finally: 
        if root:
            try: 
                root.destroy()
                logger.debug("Temporary Tk root destroyed.")
            except Exception as destroy_e:
                logger. warning(f"Error destroying temporary Tk root in browse_directory: {destroy_e}")


def get_user_input(options):
    """Give the user the chance to change the options"""
    logger.debug(f"Called get_user_input with initial options: {options}")
    initial_out_dir = options.OUT_DIR
    initial_config_file = pathlib.Path(initial_out_dir).joinpath("srum_dump_config.json")

    # --- Nested Functions ---
    def edit_config():
        logger.debug("Called edit_config (nested in get_user_input)")
        try:
            config_path_str = initial_config_file
            logger.info(f"Attempting to edit config file: {config_path_str}")
            config_path = pathlib.Path(config_path_str)
            if not config_path.exists():
                logger.warning(f"Config file does not exist, creating empty file: {config_path}")
                config_path.touch()
            
            # Use platform-appropriate file opener
            open_file_with_default_app(str(config_path))
            logger.info(f"Opened config file for editing: {config_path_str}")
        except Exception as e:
            logger.exception(f"Error opening config file for editing: {e}")
            messagebox.showerror("Error", f"Could not open config file for editing:\n{e}")

    def on_support_click(event):
        logger.debug("Called on_support_click (nested in get_user_input)")
        try:
            logger.info(f"Opening support URLs")
            webbrowser.open_new_tab("https://x.com/MarkBaggett")
            time.sleep(1)
            webbrowser.open_new_tab("https://www.linkedin.com/in/mark-baggett/")
            time.sleep(1)
            webbrowser.open_new_tab("http://youtube.com/markbaggett")
        except Exception as e:
            logger.exception(f"Error opening support links: {e}")

    def remove_topmost(window):
        logger.debug("Called remove_topmost (nested in get_user_input)")
        try:
            if window and window.winfo_exists():
                window.attributes('-topmost', False)
                logger.debug("Removed topmost attribute for main input window.")
            else:
                logger.warning("Main input window does not exist in remove_topmost.")
        except Exception as e:
            logger.exception(f"Error removing topmost attribute for main input window: {e}")

    def on_cancel():
        logger.debug("User clicked CANCEL.  Existing program.")
        root.destroy()
        sys.exit(1)

    def on_confirm():
        logger.debug("Called on_ok (nested in get_user_input)")
        try:
            out_dir_str = out_dir_entry.get()
            config_file_str = initial_config_file

            logger.debug(f"Raw paths from fields: OUT='{out_dir_str}'")

            out_dir = str(pathlib.Path(out_dir_str).resolve())

            # Validate paths
            valid = True
            if not pathlib.Path(out_dir).is_dir():
                logger. error(f"Validation failed: Output directory does not exist: {out_dir}")
                messagebox.showerror("Error", f"Output directory specified does not exist:\n{out_dir}")
                valid = False

            if valid:
                logger.info("Path validation successful.")
                options.OUT_DIR = out_dir
                logger.debug(f"Updated OUT_DIR option:  {options}")
                root.destroy()
                logger.debug("User Confirmation Window closed.")
            else:
                logger.warning("Validation failed, staying on input window.")
                return

        except Exception as e: 
            logger.exception(f"Error in on_ok handler: {e}")
            messagebox.showerror("Error", f"An unexpected error occurred:\n{e}")

    # --- Setup Main Window ---
    root = None
    try:
        root = tk.Tk()
        root.title("SRUM_DUMP 3.2")
        root.geometry("800x400")
        root.attributes('-topmost', True)
        root.after(20, remove_topmost, root)
        logger.debug("Main input window created.")
        try:
            root.iconbitmap(icon_path)
        except tk.TclError:
            logger.exception("Icon file not found or invalid.")

        image_path = os.path.join(base_path, 'srum-dump. png')
        logger.debug(f"Image path: {image_path}")

        # Logo
        logo_frame = tk.Frame(root, height=100, width=200)
        logo_frame.pack(pady=20)
        if pathlib.Path(image_path).is_file():
            logo_img = tk.PhotoImage(file=image_path)
            logo_label = tk.Label(logo_frame, image=logo_img)
            logo_label.image = logo_img
            logo_label.pack()
            logger.debug("Logo image loaded.")
        else:
            tk.Label(logo_frame, text="SRUM DUMP Logo").pack()
            logger.warning(f"Logo image not found at:  {image_path}")

        # Main content frame
        content_frame = tk.Frame(root)
        content_frame.pack(padx=20, fill=tk.BOTH, expand=True)

        # Button configuration
        button_config = {
            'width': 10,
            'height': 1,
            'padx': 5,
            'pady': 5,
            'relief': tk. RAISED,
            'borderwidth': 2,
            'bg': '#f0f0f0',
            'activebackground': '#e0e0e0'
        }

        # Configuration File section
        config_frame = tk. LabelFrame(content_frame, text='Configuration File:')
        config_frame.pack(fill=tk.X, pady=5, padx=5)
        config_input_frame = tk.Frame(config_frame)
        config_input_frame.pack(fill=tk.X, padx=5, pady=5)
        config_file_label = tk.Label(config_input_frame, width=80, anchor=tk.W, bg="lightgray", relief=tk.SUNKEN)
        config_file_label.pack(side=tk. LEFT, expand=True, fill=tk.X, pady=5)
        config_file_label.config(text=initial_config_file)
        
        edit_btn = tk.Button(
            config_input_frame,
            text="Edit",
            command=edit_config,
            **button_config
        )
        edit_btn.pack(side=tk.LEFT, padx=5)
        edit_btn.bind("<Enter>", lambda e: edit_btn.config(bg="#e0e0e0"))
        edit_btn.bind("<Leave>", lambda e: edit_btn. config(bg="#f0f0f0"))

        # Output Directory section
        output_frame = tk.LabelFrame(content_frame, text='Output folder:')
        output_frame. pack(fill=tk.X, pady=5, padx=5)
        output_input_frame = tk.Frame(output_frame)
        output_input_frame.pack(fill=tk.X, padx=5, pady=5)
        out_dir_entry = tk.Entry(output_input_frame, width=80)
        out_dir_entry. pack(side=tk.LEFT, expand=True, fill=tk. X, pady=5)
        out_dir_entry.insert(0, initial_out_dir)
        
        def browse_with_restore():
            initial_value = out_dir_entry.get()
            new_dir = browse_directory(out_dir_entry.get() or initial_out_dir)
            if new_dir:
                out_dir_entry.delete(0, tk. END)
                out_dir_entry.insert(0, new_dir)
            else:
                out_dir_entry.delete(0, tk.END)
                out_dir_entry.insert(0, initial_value)

        browse_btn = tk.Button(
            output_input_frame,
            text="Browse",
            command=browse_with_restore,
            **button_config
        )
        browse_btn.pack(side=tk. LEFT, padx=5)
        browse_btn.bind("<Enter>", lambda e: browse_btn.config(bg="#e0e0e0"))
        browse_btn.bind("<Leave>", lambda e: browse_btn.config(bg="#f0f0f0"))

        # Support link
        support_label = tk.Label(root, text="Click here for support or to reach the tool author.",
                            fg="blue", cursor="hand2")
        support_label.pack(pady=10)
        support_label.bind("<Button-1>", on_support_click)

        # Action buttons
        button_frame = tk.Frame(root)
        button_frame.pack(pady=10)
        
        confirm_btn = tk.Button(
            button_frame,
            text="Confirm",
            command=on_confirm,
            **button_config
        )
        confirm_btn.pack(side=tk.LEFT, padx=10)
        confirm_btn.bind("<Enter>", lambda e: confirm_btn.config(bg="#e0e0e0"))
        confirm_btn.bind("<Leave>", lambda e: confirm_btn. config(bg="#f0f0f0"))

        cancel_btn = tk.Button(
            button_frame,
            text="Cancel",
            command=on_cancel,
            **button_config
        )
        cancel_btn. pack(side=tk.LEFT, padx=10)
        cancel_btn.bind("<Enter>", lambda e: cancel_btn.config(bg="#e0e0e0"))
        cancel_btn. bind("<Leave>", lambda e:  cancel_btn.config(bg="#f0f0f0"))

        logger.debug("Starting main input window mainloop.")
        root.mainloop()
        logger.debug("Main input window mainloop finished.")
    except Exception as e:
        logger.exception(f"Error setting up or running get_user_input main window: {e}")
        try:
            messagebox.showerror("Fatal Error", f"Could not initialize the main input window:\n{e}")
        except:
            logger.exception(f"FATAL ERROR: Could not initialize the main input window:  {e}", file=sys.stderr)
        sys.exit(1)

    logger.debug("Exiting get_user_input function.")


def get_input_wizard(options):
    # (Keep the existing implementation - it's already compatible)
    # Just ensure it uses the updated browse functions
    pass