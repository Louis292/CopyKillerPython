import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import hashlib
from datetime import datetime
from collections import defaultdict
from pathlib import Path
import threading
import queue
from typing import List, Dict
import time
import json

class ConfigManager:
    """
    Handles the loading, saving and management of application configuration.
    Provides default values if no configuration file exists.
    """
    DEFAULT_CONFIG = {
        "window_title": "Duplicate File Finder",
        "extensions": {
            "images": [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp"],
            "documents": [".pdf", ".doc", ".docx", ".txt", ".rtf"],
            "audio": [".mp3", ".wav", ".flac", ".m4a", ".ogg"],
            "video": [".mp4", ".avi", ".mkv", ".mov", ".wmv"]
        },
        "enabled_categories": ["images"],
        "window_size": {
            "width": 700,
            "height": 500
        }
    }

    def __init__(self):
        """Initialize the configuration manager and load the config file."""
        self.config_path = "config.json"
        self.config = self.load_config()

    def load_config(self) -> dict:
        """
        Load configuration from JSON file or create default if not exists.
        
        Returns:
            dict: The loaded configuration or default configuration
        """
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            else:
                self.save_config(self.DEFAULT_CONFIG)
                return self.DEFAULT_CONFIG
        except Exception as e:
            print(f"Error loading configuration: {e}")
            return self.DEFAULT_CONFIG

    def save_config(self, config: dict) -> None:
        """
        Save configuration to JSON file.
        
        Args:
            config (dict): Configuration to save
        """
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4, ensure_ascii=False)
        except Exception as e:
            print(f"Error saving configuration: {e}")

    def get_enabled_extensions(self) -> set:
        """
        Get all enabled file extensions from the configuration.
        
        Returns:
            set: Set of enabled file extensions
        """
        extensions = set()
        for category in self.config["enabled_categories"]:
            if category in self.config["extensions"]:
                extensions.update(self.config["extensions"][category])
        return extensions

class DuplicateFinderApp:
    """
    Main application class for the duplicate file finder.
    Handles the GUI and file processing logic.
    """
    
    def __init__(self, root):
        """
        Initialize the application.
        
        Args:
            root: The root Tkinter window
        """
        self.config_manager = ConfigManager()
        self.root = root
        self.root.title(self.config_manager.config["window_title"])
        width = self.config_manager.config["window_size"]["width"]
        height = self.config_manager.config["window_size"]["height"]
        self.root.geometry(f"{width}x{height}")
        
        # Initialize variables
        self.folder_path = tk.StringVar()
        self.status_text = tk.StringVar()
        self.status_text.set("Waiting for folder selection...")
        self.processing = False
        self.file_queue = queue.Queue()
        self.result_queue = queue.Queue()
        
        # Create GUI elements
        self.create_widgets()
    
    def create_widgets(self):
        """Create and configure all GUI widgets."""
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure resizing behavior
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        
        # Create configuration menu
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        config_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Configuration", menu=config_menu)
        config_menu.add_command(label="Manage Extensions", command=self.show_extension_manager)
        
        # Folder selection button
        ttk.Button(main_frame, text="Select Folder", 
                  command=self.browse_folder).grid(row=0, column=0, pady=10, sticky=tk.W)
        
        # Selected path display
        ttk.Label(main_frame, textvariable=self.folder_path, wraplength=600).grid(
            row=1, column=0, pady=5, sticky=tk.W)
        
        # Search button
        self.search_button = ttk.Button(main_frame, text="Find and Remove Duplicates",
                                      command=self.start_processing)
        self.search_button.grid(row=2, column=0, pady=10, sticky=tk.W)
        
        # Stop button
        self.stop_button = ttk.Button(main_frame, text="Stop", command=self.stop_processing,
                                    state=tk.DISABLED)
        self.stop_button.grid(row=2, column=0, pady=10, padx=(200,0), sticky=tk.W)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(main_frame, variable=self.progress_var,
                                      maximum=100, mode='determinate')
        self.progress.grid(row=3, column=0, pady=10, sticky=(tk.W, tk.E))
        
        # Status display
        ttk.Label(main_frame, textvariable=self.status_text, wraplength=600).grid(
            row=4, column=0, pady=5, sticky=tk.W)
        
        # Log area
        self.log_text = tk.Text(main_frame, height=10, width=70, wrap=tk.WORD)
        self.log_text.grid(row=5, column=0, pady=5, sticky=(tk.W, tk.E))
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=self.log_text.yview)
        scrollbar.grid(row=5, column=1, sticky=(tk.N, tk.S))
        self.log_text.configure(yscrollcommand=scrollbar.set)

    def show_extension_manager(self):
        """Show the extension management window."""
        config_window = tk.Toplevel(self.root)
        config_window.title("Extension Manager")
        config_window.geometry("400x300")
        
        # Variables for checkboxes
        category_vars = {}
        
        def save_categories():
            """Save the selected categories and close the window."""
            enabled_categories = [cat for cat, var in category_vars.items() if var.get()]
            self.config_manager.config["enabled_categories"] = enabled_categories
            self.config_manager.save_config(self.config_manager.config)
            config_window.destroy()
            self.log_message("Extension configuration updated")
        
        # Create checkboxes for each category
        for i, category in enumerate(self.config_manager.config["extensions"].keys()):
            var = tk.BooleanVar(value=category in self.config_manager.config["enabled_categories"])
            category_vars[category] = var
            
            frame = ttk.Frame(config_window)
            frame.pack(fill=tk.X, padx=10, pady=5)
            
            cb = ttk.Checkbutton(frame, text=category.capitalize(), variable=var)
            cb.pack(side=tk.LEFT)
            
            # Show extensions for this category
            extensions = ", ".join(self.config_manager.config["extensions"][category])
            ttk.Label(frame, text=f"({extensions})", wraplength=250).pack(side=tk.LEFT, padx=10)
        
        ttk.Button(config_window, text="Save", command=save_categories).pack(pady=20)

    def log_message(self, message: str):
        """
        Add a message to the log area.
        
        Args:
            message (str): Message to log
        """
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()

    def browse_folder(self):
        """Open folder selection dialog and update the path."""
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            self.folder_path.set(folder_selected)
            self.status_text.set("Folder selected. Ready to search.")
            self.log_message(f"Selected folder: {folder_selected}")

    def get_file_hash(self, filepath: str) -> str:
        """
        Calculate MD5 hash of a file.
        
        Args:
            filepath (str): Path to the file
            
        Returns:
            str: MD5 hash of the file
            
        Raises:
            InterruptedError: If the process is stopped by the user
        """
        try:
            hash_md5 = hashlib.md5()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    if not self.processing:  # Allow stopping during hash calculation
                        raise InterruptedError("Process stopped by user")
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except (IOError, OSError) as e:
            self.log_message(f"Error calculating hash for {filepath}: {e}")
            return None
        except InterruptedError:
            raise

    def process_files(self):
        """
        Process files in the selected folder to find and remove duplicates.
        This method runs in a separate thread.
        """
        files_by_hash = defaultdict(list)
        total_files = 0
        processed_files = 0
        
        try:
            # Get enabled extensions
            enabled_extensions = self.config_manager.get_enabled_extensions()
            
            # First pass: count total files
            for root_dir, _, files in os.walk(self.folder_path.get()):
                if not self.processing:
                    break
                for filename in files:
                    if Path(filename).suffix.lower() in enabled_extensions:
                        total_files += 1
            
            # Second pass: process files
            for root_dir, _, files in os.walk(self.folder_path.get()):
                if not self.processing:
                    break
                for filename in files:
                    if not self.processing:
                        break
                    
                    if Path(filename).suffix.lower() in enabled_extensions:
                        filepath = os.path.join(root_dir, filename)
                        try:
                            file_hash = self.get_file_hash(filepath)
                            if file_hash:
                                files_by_hash[file_hash].append(filepath)
                            processed_files += 1
                            progress = (processed_files / total_files) * 100 if total_files > 0 else 0
                            self.result_queue.put(("progress", progress))
                            self.result_queue.put(("status", f"Processing: {processed_files}/{total_files} files"))
                        except InterruptedError:
                            return
                        except Exception as e:
                            self.result_queue.put(("log", f"Error with {filepath}: {str(e)}"))
            
            # Process duplicates
            if self.processing:
                duplicates_found = 0
                files_removed = 0
                
                for file_hash, file_list in files_by_hash.items():
                    if not self.processing:
                        break
                    
                    if len(file_list) > 1:
                        duplicates_found += len(file_list) - 1
                        sorted_files = sorted(file_list, key=lambda x: os.path.getmtime(x))
                        for duplicate in sorted_files[1:]:
                            if not self.processing:
                                break
                            try:
                                os.remove(duplicate)
                                files_removed += 1
                                self.result_queue.put(("log", f"Removed: {duplicate}"))
                            except OSError as e:
                                self.result_queue.put(("log", f"Error removing {duplicate}: {e}"))
                
                self.result_queue.put(("final", f"Completed!\nDuplicates found: {duplicates_found}\n"
                                              f"Files removed: {files_removed}"))
            
        except Exception as e:
            self.result_queue.put(("error", f"An error occurred: {str(e)}"))
        finally:
            self.result_queue.put(("done", None))

    def update_ui(self):
        """Update the UI with results from the processing thread."""
        try:
            while True:
                try:
                    msg_type, data = self.result_queue.get_nowait()
                    
                    if msg_type == "progress":
                        self.progress_var.set(data)
                    elif msg_type == "status":
                        self.status_text.set(data)
                    elif msg_type == "log":
                        self.log_message(data)
                    elif msg_type == "error":
                        messagebox.showerror("Error", data)
                        self.stop_processing()
                    elif msg_type == "final":
                        self.status_text.set(data)
                    elif msg_type == "done":
                        self.processing = False
                        self.search_button.config(state=tk.NORMAL)
                        self.stop_button.config(state=tk.DISABLED)
                        return
                    
                except queue.Empty:
                    break
                
            if self.processing:
                self.root.after(100, self.update_ui)
                
        except Exception as e:
            self.log_message(f"Error updating UI: {e}")
            self.stop_processing()

    def start_processing(self):
        """Start the file processing in a separate thread."""
        if not self.folder_path.get():
            messagebox.showerror("Error", "Please select a folder")
            return
        
        self.processing = True
        self.search_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.progress_var.set(0)
        self.log_text.delete(1.0, tk.END)
        self.log_message("Starting processing...")
        
        # Start processing thread
        threading.Thread(target=self.process_files, daemon=True).start()
        # Start UI updates
        self.update_ui()

    def stop_processing(self):
        """Stop the current processing operation."""
        self.processing = False
        self.status_text.set("Processing stopped by user")
        self.search_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = DuplicateFinderApp(root)
    root.mainloop()