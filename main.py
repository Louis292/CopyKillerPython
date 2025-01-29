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

class DuplicateFinderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Détecteur de fichiers en double")
        self.root.geometry("700x500")
        
        # Variables
        self.folder_path = tk.StringVar()
        self.status_text = tk.StringVar()
        self.status_text.set("En attente de sélection du dossier...")
        self.processing = False
        self.file_queue = queue.Queue()
        self.result_queue = queue.Queue()
        
        # Création de l'interface
        self.create_widgets()
        
    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configuration du redimensionnement
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        
        # Bouton de sélection du dossier
        ttk.Button(main_frame, text="Sélectionner le dossier", 
                  command=self.browse_folder).grid(row=0, column=0, pady=10, sticky=tk.W)
        
        # Affichage du chemin sélectionné
        ttk.Label(main_frame, textvariable=self.folder_path, wraplength=600).grid(
            row=1, column=0, pady=5, sticky=tk.W)
        
        # Bouton de recherche des doublons
        self.search_button = ttk.Button(main_frame, text="Rechercher et supprimer les doublons",
                                      command=self.start_processing)
        self.search_button.grid(row=2, column=0, pady=10, sticky=tk.W)
        
        # Bouton d'arrêt
        self.stop_button = ttk.Button(main_frame, text="Arrêter", command=self.stop_processing,
                                    state=tk.DISABLED)
        self.stop_button.grid(row=2, column=0, pady=10, padx=(200,0), sticky=tk.W)
        
        # Barre de progression
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(main_frame, variable=self.progress_var,
                                      maximum=100, mode='determinate')
        self.progress.grid(row=3, column=0, pady=10, sticky=(tk.W, tk.E))
        
        # Status
        ttk.Label(main_frame, textvariable=self.status_text, wraplength=600).grid(
            row=4, column=0, pady=5, sticky=tk.W)
        
        # Zone de log
        self.log_text = tk.Text(main_frame, height=10, width=70, wrap=tk.WORD)
        self.log_text.grid(row=5, column=0, pady=5, sticky=(tk.W, tk.E))
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=self.log_text.yview)
        scrollbar.grid(row=5, column=1, sticky=(tk.N, tk.S))
        self.log_text.configure(yscrollcommand=scrollbar.set)
    
    def log_message(self, message: str):
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()
    
    def browse_folder(self):
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            self.folder_path.set(folder_selected)
            self.status_text.set("Dossier sélectionné. Prêt pour la recherche.")
            self.log_message(f"Dossier sélectionné : {folder_selected}")
    
    def get_file_hash(self, filepath: str) -> str:
        """Calcule le hash MD5 d'un fichier de manière sécurisée"""
        try:
            hash_md5 = hashlib.md5()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    if not self.processing:  # Permet l'arrêt pendant le calcul du hash
                        raise InterruptedError("Processus arrêté par l'utilisateur")
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except (IOError, OSError) as e:
            self.log_message(f"Erreur lors du calcul du hash de {filepath}: {e}")
            return None
        except InterruptedError:
            raise
    
    def process_files(self):
        """Fonction exécutée dans le thread de traitement"""
        files_by_hash = defaultdict(list)
        total_files = 0
        processed_files = 0
        
        try:
            # Première passe : compte le nombre total de fichiers
            image_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp'}
            for root_dir, _, files in os.walk(self.folder_path.get()):
                if not self.processing:
                    break
                for filename in files:
                    if Path(filename).suffix.lower() in image_extensions:
                        total_files += 1
            
            # Deuxième passe : traitement des fichiers
            for root_dir, _, files in os.walk(self.folder_path.get()):
                if not self.processing:
                    break
                for filename in files:
                    if not self.processing:
                        break
                    
                    if Path(filename).suffix.lower() in image_extensions:
                        filepath = os.path.join(root_dir, filename)
                        try:
                            file_hash = self.get_file_hash(filepath)
                            if file_hash:
                                files_by_hash[file_hash].append(filepath)
                            processed_files += 1
                            progress = (processed_files / total_files) * 100
                            self.result_queue.put(("progress", progress))
                            self.result_queue.put(("status", f"Traitement : {processed_files}/{total_files} fichiers"))
                        except InterruptedError:
                            return
                        except Exception as e:
                            self.result_queue.put(("log", f"Erreur avec {filepath}: {str(e)}"))
            
            # Traitement des doublons
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
                                self.result_queue.put(("log", f"Supprimé : {duplicate}"))
                            except OSError as e:
                                self.result_queue.put(("log", f"Erreur lors de la suppression de {duplicate}: {e}"))
                
                self.result_queue.put(("final", f"Terminé!\nDoublons trouvés: {duplicates_found}\n"
                                              f"Fichiers supprimés: {files_removed}"))
            
        except Exception as e:
            self.result_queue.put(("error", f"Une erreur est survenue: {str(e)}"))
        finally:
            self.result_queue.put(("done", None))
    
    def update_ui(self):
        """Met à jour l'interface utilisateur avec les résultats du thread"""
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
                        messagebox.showerror("Erreur", data)
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
            self.log_message(f"Erreur lors de la mise à jour de l'interface: {e}")
            self.stop_processing()
    
    def start_processing(self):
        """Démarre le traitement dans un thread séparé"""
        if not self.folder_path.get():
            messagebox.showerror("Erreur", "Veuillez sélectionner un dossier")
            return
        
        self.processing = True
        self.search_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.progress_var.set(0)
        self.log_text.delete(1.0, tk.END)
        self.log_message("Démarrage du traitement...")
        
        # Démarre le thread de traitement
        threading.Thread(target=self.process_files, daemon=True).start()
        # Démarre la mise à jour de l'interface
        self.update_ui()
    
    def stop_processing(self):
        """Arrête le traitement en cours"""
        self.processing = False
        self.status_text.set("Traitement arrêté par l'utilisateur")
        self.search_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = DuplicateFinderApp(root)
    root.mainloop()