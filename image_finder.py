import os
import sys
import sqlite3
import hashlib
import json
import threading
import queue
import platform
import subprocess
import re
from datetime import datetime

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from tkinter import Menu

from PIL import Image, ImageTk, ExifTags, ImageGrab
import imagehash

# --- OPTIONAL DRAG & DROP SUPPORT ---
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    HAS_DND = True
except ImportError:
    HAS_DND = False
    print("Note: Install 'tkinterdnd2' to enable Drag & Drop support (pip install tkinterdnd2)")

# --- CONFIGURATION ---
DB_NAME = "image_hashes.db"
CONFIG_FILE = "config.json"
ICON_NAME = "app_icon.ico"

# Dark Theme Colors
COLOR_BG = "#2b2b2b"
COLOR_FG = "#ffffff"
COLOR_ACCENT = "#4CAF50"  # Green
COLOR_ACCENT_HOVER = "#45a049"
COLOR_LIST_BG = "#363636"
COLOR_LIST_FG = "#eeeeee"

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    # File hashes table
    c.execute('''CREATE TABLE IF NOT EXISTS files 
                 (path TEXT PRIMARY KEY, mtime REAL, p_hash TEXT)''')
    # Roots table to track scan sessions for grouping
    c.execute('''CREATE TABLE IF NOT EXISTS scan_roots 
                 (path TEXT PRIMARY KEY)''')
    conn.commit()
    conn.close()

class CacheManager(tk.Toplevel):
    """
    Window to manage/delete cached folder data.
    Groups files by the 'Scan Root' to avoid listing hundreds of subfolders.
    """
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Cache Manager")
        self.geometry("700x600") # Increased height to prevent cropping
        self.configure(bg=COLOR_BG)
        
        # Styles
        style = ttk.Style()
        style.configure("Treeview", rowheight=30)

        # Header
        lbl_info = tk.Label(self, text="Manage Cached Hash Data", font=("Segoe UI", 12, "bold"), bg=COLOR_BG, fg=COLOR_FG)
        lbl_info.pack(pady=10)

        hint_text = (
            "Tip: Folders are grouped by your scan selection.\n"
            "Removing a folder deletes the index for it and all its subfolders."
        )
        lbl_desc = tk.Label(self, text=hint_text, 
                          bg=COLOR_BG, fg="#aaaaaa", justify=tk.CENTER)
        lbl_desc.pack(pady=(0, 10))

        # --- TREEVIEW & SCROLLBAR ---
        frame_list = tk.Frame(self, bg=COLOR_BG)
        frame_list.pack(fill=tk.BOTH, expand=True, padx=10)
        
        columns = ("Folder", "Count", "Status")
        self.tree = ttk.Treeview(frame_list, columns=columns, show='headings', selectmode="extended")
        
        # Columns
        self.tree.heading("Folder", text="Root Folder", anchor=tk.W)
        self.tree.heading("Count", text="Cached Images", anchor=tk.CENTER)
        self.tree.heading("Status", text="Status", anchor=tk.CENTER)
        
        self.tree.column("Folder", width=450, stretch=True)
        self.tree.column("Count", width=100, anchor=tk.CENTER, stretch=True)
        self.tree.column("Status", width=100, anchor=tk.CENTER, stretch=True)

        # Scrollbar (Packed Right, Fill Y)
        vsb = ttk.Scrollbar(frame_list, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        
        # Pack Scrollbar FIRST to ensure it stays on the right edge
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        # Pack Tree SECOND to fill remaining space
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # --- BUTTONS (Stacked) ---
        frame_btn = tk.Frame(self, bg=COLOR_BG)
        frame_btn.pack(fill=tk.X, padx=10, pady=15)

        # Refresh Button (Top)
        btn_refresh = tk.Button(frame_btn, text="Refresh List", command=self.load_data, 
                              bg="#444444", fg="white", relief=tk.FLAT, padx=10, pady=5)
        btn_refresh.pack(fill=tk.X, pady=(0, 5)) # Add gap below

        # Delete Button (Bottom)
        btn_delete = tk.Button(frame_btn, text="Remove Selected from Index", command=self.delete_selected, 
                             bg="#F44336", fg="white", relief=tk.FLAT, padx=10, pady=5)
        btn_delete.pack(fill=tk.X)

        self.load_data()

    def load_data(self):
        # Clear tree
        for item in self.tree.get_children():
            self.tree.delete(item)

        try:
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            
            # 1. Load registered Scan Roots
            c.execute("SELECT path FROM scan_roots")
            # Store roots as (original, normalized) for robust matching
            roots = []
            is_win = platform.system() == "Windows"
            for r in c.fetchall():
                path = r[0]
                norm = os.path.normpath(path).lower() if is_win else os.path.normpath(path)
                roots.append((path, norm))
            
            # 2. Load all file paths
            c.execute("SELECT path FROM files")
            all_files = c.fetchall()
            
            conn.close()

            # 3. Group files
            groups = {} # folder_path -> count

            for row in all_files:
                f_path = row[0]
                f_norm = os.path.normpath(f_path).lower() if is_win else os.path.normpath(f_path)
                
                matched_root = None
                best_len = -1
                
                # Try to find a registered root that contains this file
                for r_orig, r_norm in roots:
                    # Check if file is inside root (exact match or subdirectory)
                    if f_norm == r_norm or f_norm.startswith(r_norm + os.sep):
                        if len(r_norm) > best_len:
                            matched_root = r_orig
                            best_len = len(r_norm)
                
                if matched_root:
                    groups[matched_root] = groups.get(matched_root, 0) + 1
                else:
                    # Legacy data / Uncategorized: Group by immediate parent folder
                    parent = os.path.dirname(f_path)
                    groups[parent] = groups.get(parent, 0) + 1

            # 4. Display
            for folder in sorted(groups.keys()):
                status = "Found" if os.path.exists(folder) else "Missing"
                self.tree.insert("", "end", values=(folder, groups[folder], status))

        except Exception as e:
            messagebox.showerror("Error", f"Failed to load cache: {e}")

    def delete_selected(self):
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showinfo("Info", "No folder selected.")
            return

        confirm = messagebox.askyesno("Confirm", f"Remove index data for {len(selected_items)} folders?\n(Files will remain on disk)")
        if not confirm:
            return

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        
        try:
            for item in selected_items:
                vals = self.tree.item(item, 'values')
                folder_path = vals[0]
                
                # 1. Remove files from index
                # Pattern: folder itself OR folder + separator + wildcard
                pattern = os.path.join(folder_path, "%")
                c.execute("DELETE FROM files WHERE path LIKE ?", (pattern,))
                c.execute("DELETE FROM files WHERE path = ?", (folder_path,))
                
                # 2. Remove from roots registry (if it was a root)
                c.execute("DELETE FROM scan_roots WHERE path = ?", (folder_path,))
            
            conn.commit()
            messagebox.showinfo("Success", "Cache updated.")
            self.load_data()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete: {e}")
        finally:
            conn.close()

class ImageScanner(threading.Thread):
    """
    Background thread to scan folders and hash images.
    """
    def __init__(self, folder_path, input_image_path, result_queue, status_queue):
        super().__init__()
        self.folder_path = folder_path
        self.input_image_path = input_image_path
        self.result_queue = result_queue
        self.status_queue = status_queue
        self.is_running = True
        self.daemon = True 

    def calculate_hash(self, image_path):
        try:
            img = Image.open(image_path)
            # Average Hash (aHash) - Best for finding sources/screenshots
            h = str(imagehash.average_hash(img))
            return h
        except Exception:
            return None

    def run(self):
        if not self.folder_path or not self.input_image_path:
            return

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        
        # --- NEW: Register Scan Root for Grouping ---
        try:
            c.execute("INSERT OR IGNORE INTO scan_roots (path) VALUES (?)", (self.folder_path,))
            conn.commit()
        except Exception:
            pass

        self.status_queue.put(("status", "Calculating input hash..."))
        input_hash = self.calculate_hash(self.input_image_path)
        
        if not input_hash:
            self.status_queue.put(("status", "Error: Could not read input image."))
            self.status_queue.put(("done", None))
            conn.close()
            return

        # --- OPTIMIZATION: Preload DB Cache ---
        self.status_queue.put(("status", "Loading cache into memory..."))
        db_cache = {}
        try:
            c.execute("SELECT path, mtime, p_hash FROM files")
            rows = c.fetchall()
            for r in rows:
                db_cache[r[0]] = (r[1], r[2])
        except Exception as e:
            print(f"Cache load error: {e}")
            db_cache = {}

        image_extensions = {'.jpg', '.jpeg', '.png', '.bmp', '.webp', '.tiff'}
        files_to_process = []

        # 1. Discovery Phase
        self.status_queue.put(("status", "Scanning directory..."))
        count_found = 0
        for root, dirs, files in os.walk(self.folder_path):
            if not self.is_running: break
            for file in files:
                if os.path.splitext(file)[1].lower() in image_extensions:
                    full_path = os.path.join(root, file)
                    files_to_process.append(full_path)
                    count_found += 1
                    
                    if count_found % 500 == 0:
                         self.status_queue.put(("status", f"Found {count_found} files..."))

        total_files = len(files_to_process)
        
        # 2. Match Phase
        self.status_queue.put(("status", f"Processing {total_files} images..."))
        
        batch_counter = 0
        ref_hash_obj = imagehash.hex_to_hash(input_hash)

        for index, file_path in enumerate(files_to_process):
            if not self.is_running: break
            
            try:
                try:
                    mtime = os.path.getmtime(file_path)
                except FileNotFoundError:
                    continue 
                
                file_hash_str = None
                
                # Check Memory Cache
                if file_path in db_cache:
                    cached_mtime, cached_hash = db_cache[file_path]
                    if cached_mtime == mtime:
                        file_hash_str = cached_hash
                
                # Calculate if missing or changed
                if not file_hash_str:
                    file_hash_str = self.calculate_hash(file_path)
                    if file_hash_str:
                        # Write to DB
                        c.execute("INSERT OR REPLACE INTO files (path, mtime, p_hash) VALUES (?, ?, ?)",
                                  (file_path, mtime, file_hash_str))
                        batch_counter += 1

                # Compare
                if file_hash_str:
                    dist = ref_hash_obj - imagehash.hex_to_hash(file_hash_str)
                    
                    if dist <= 5: 
                        file_stat = os.stat(file_path)
                        size_mb = file_stat.st_size / (1024 * 1024)
                        
                        result_data = {
                            "path": file_path,
                            "name": os.path.basename(file_path),
                            "size": f"{size_mb:.2f} MB",
                            "distance": dist
                        }
                        self.result_queue.put(result_data)

            except Exception:
                pass

            # Update progress
            if index % 20 == 0:
                progress = (index + 1) / total_files * 100
                self.status_queue.put(("progress", progress))
                self.status_queue.put(("status", f"Scanning: {index+1}/{total_files}"))

            if batch_counter >= 500:
                conn.commit()
                batch_counter = 0

        if batch_counter > 0:
            conn.commit()
            
        conn.close()
        self.status_queue.put(("status", "Scan Complete."))
        self.status_queue.put(("done", None))

    def stop(self):
        self.is_running = False

# Select Base Class based on DND availability
BaseClass = TkinterDnD.Tk if HAS_DND else tk.Tk

class App(BaseClass):
    def __init__(self):
        super().__init__()
        init_db()
        self.title("SourceSeeker AI - Local Reverse Image Search & Metadata Viewer")
        self.geometry("1100x750")
        
        # --- ICON LOADING (PyInstaller Compatible) ---
        icon_path = resource_path(ICON_NAME)
        if os.path.exists(icon_path):
            try:
                self.iconbitmap(icon_path)
            except Exception as e:
                print(f"Warning: Could not load icon: {e}")
        
        # Apply Custom Theme
        self.configure(bg=COLOR_BG)
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self.style.configure("TFrame", background=COLOR_BG)
        self.style.configure("TLabel", background=COLOR_BG, foreground=COLOR_FG)
        self.style.configure("TButton", background="#444444", foreground="white", borderwidth=1)
        self.style.map("TButton", background=[("active", "#666666")])
        
        # Treeview Theme
        self.style.configure("Treeview", 
                           background=COLOR_LIST_BG, 
                           foreground=COLOR_LIST_FG, 
                           fieldbackground=COLOR_LIST_BG,
                           rowheight=60)
        self.style.map("Treeview", background=[("selected", COLOR_ACCENT)])

        self.target_folder = ""
        self.input_image_path = ""
        self.scanner_thread = None
        
        self.image_cache = [] # Prevent GC
        self.result_queue = queue.Queue()
        self.status_queue = queue.Queue()

        self.load_config()
        self.setup_ui()
        self.check_ready()
        self.check_queue()

    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    data = json.load(f)
                    self.target_folder = data.get("last_folder", "")
            except Exception:
                pass

    def save_config(self):
        data = {"last_folder": self.target_folder}
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(data, f)
        except Exception:
            pass

    def setup_ui(self):
        # --- STATUS BAR ---
        self.status_frame = tk.Frame(self, bg="#222222", height=25)
        self.status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.lbl_status = tk.Label(self.status_frame, text="Ready", bg="#222222", fg="#aaaaaa", font=("Segoe UI", 9))
        self.lbl_status.pack(side=tk.LEFT, padx=10)
        
        self.progress = ttk.Progressbar(self.status_frame, orient=tk.HORIZONTAL, length=200, mode='determinate')
        self.progress.pack(side=tk.RIGHT, padx=5, pady=3)

        # --- MAIN SPLIT ---
        main_pane = tk.PanedWindow(self, orient=tk.HORIZONTAL, sashrelief=tk.FLAT, bg=COLOR_BG, sashwidth=4)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # --- LEFT PANEL (Controls) ---
        left_frame = tk.Frame(main_pane, bg=COLOR_BG)
        main_pane.add(left_frame, minsize=260)

        # 1. Reference Image
        tk.Label(left_frame, text="Reference Image", font=("Segoe UI", 11, "bold"), bg=COLOR_BG, fg=COLOR_FG).pack(pady=(5, 5), anchor="w")
        
        drop_text = "[No Image]\nDrag & Drop Here" if HAS_DND else "[No Image]"
        self.lbl_preview = tk.Label(left_frame, text=drop_text, bg="#1e1e1e", fg="#555555", width=30, height=10, relief=tk.FLAT)
        self.lbl_preview.pack(pady=5, fill=tk.X)
        
        # REGISTER DROP TARGET
        if HAS_DND:
            try:
                self.lbl_preview.drop_target_register(DND_FILES)
                self.lbl_preview.dnd_bind('<<Drop>>', self.on_drop)
                self.drop_target_register(DND_FILES)
                self.dnd_bind('<<Drop>>', self.on_drop)
            except Exception as e:
                print(f"DND Init Error: {e}")

        btn_browse = tk.Button(left_frame, text="📂 Browse Image", command=self.browse_image, 
                             bg="#444444", fg="white", relief=tk.FLAT, pady=5)
        btn_browse.pack(fill=tk.X, pady=2)
        
        btn_paste = tk.Button(left_frame, text="📋 Paste Clipboard", command=self.paste_clipboard,
                            bg="#444444", fg="white", relief=tk.FLAT, pady=5)
        btn_paste.pack(fill=tk.X, pady=2)

        tk.Frame(left_frame, height=1, bg="#555555").pack(fill=tk.X, pady=15)

        # 2. Location
        tk.Label(left_frame, text="Search Location", font=("Segoe UI", 11, "bold"), bg=COLOR_BG, fg=COLOR_FG).pack(anchor="w")
        
        display_folder = self.target_folder if self.target_folder else "No folder selected"
        self.lbl_folder = tk.Label(left_frame, text=display_folder, fg="#aaaaaa", bg=COLOR_BG, wraplength=240, justify=tk.LEFT)
        self.lbl_folder.pack(pady=5, anchor="w")
        
        btn_folder = tk.Button(left_frame, text="📂 Select Folder", command=self.select_folder,
                             bg="#444444", fg="white", relief=tk.FLAT, pady=5)
        btn_folder.pack(fill=tk.X, pady=2)

        # 3. Cache Management (NEW)
        btn_cache = tk.Button(left_frame, text="⚙ Manage Cache", command=self.open_cache_manager,
                            bg="#333333", fg="white", relief=tk.FLAT, pady=5)
        btn_cache.pack(fill=tk.X, pady=(5, 0))

        # 4. Start Button (Big)
        self.btn_search = tk.Button(left_frame, text="START SCAN", command=self.toggle_scan, 
                                    bg=COLOR_ACCENT, fg="white", font=("Segoe UI", 12, "bold"), 
                                    state=tk.DISABLED, relief=tk.FLAT, pady=10)
        self.btn_search.pack(fill=tk.X, pady=20, side=tk.BOTTOM)


        # --- RIGHT PANEL (Results & Meta) ---
        right_pane = tk.PanedWindow(main_pane, orient=tk.VERTICAL, sashrelief=tk.FLAT, bg=COLOR_BG, sashwidth=4)
        main_pane.add(right_pane)

        # Treeview (Top Right)
        tree_frame = tk.Frame(right_pane, bg=COLOR_BG)
        right_pane.add(tree_frame, height=450)

        cols = ("Filename", "Distance", "Size", "Path")
        self.tree = ttk.Treeview(tree_frame, columns=cols, show='tree headings', selectmode="browse")
        
        self.tree.column("#0", width=80, anchor="center") # Thumbnail
        self.tree.heading("#0", text="Img")

        self.tree.heading("Filename", text="File Name")
        self.tree.column("Filename", width=150)
        
        self.tree.heading("Distance", text="Diff") # Hamming distance
        self.tree.column("Distance", width=50, anchor="center")
        
        self.tree.heading("Size", text="Size")
        self.tree.column("Size", width=80, anchor="e")

        self.tree.heading("Path", text="Full Path") # Hidden mostly
        
        # Scrollbar
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # Bindings
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)
        self.tree.bind("<Double-1>", self.on_double_click)
        self.tree.bind("<Button-3>", self.show_context_menu)
        self.tree.bind("<Delete>", self.on_delete_key) 

        # Metadata (Bottom Right)
        meta_frame = tk.Frame(right_pane, bg=COLOR_BG)
        right_pane.add(meta_frame)
        
        meta_header = tk.Frame(meta_frame, bg=COLOR_BG)
        meta_header.pack(fill=tk.X, padx=5, pady=5)

        tk.Label(meta_header, text="Metadata / Prompts", font=("Segoe UI", 9, "bold"), bg=COLOR_BG, fg=COLOR_FG).pack(side=tk.LEFT)
        
        def make_btn(parent, text, cmd):
            return tk.Button(parent, text=text, command=cmd, font=("Segoe UI", 8), bg="#444444", fg="white", relief=tk.FLAT)

        make_btn(meta_header, "Copy All", self.copy_all_metadata).pack(side=tk.RIGHT, padx=2)
        make_btn(meta_header, "Copy Seed", self.copy_seed).pack(side=tk.RIGHT, padx=2)

        self.txt_meta = scrolledtext.ScrolledText(meta_frame, font=("Consolas", 9), state=tk.NORMAL, bg="#1e1e1e", fg="#dcdcdc", insertbackground="white")
        self.txt_meta.bind("<Key>", lambda e: self.block_edit(e))
        self.txt_meta.bind("<Control-a>", self.select_all_text)
        self.txt_meta.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Context Menu
        self.context_menu = Menu(self, tearoff=0, bg="#2b2b2b", fg="white")
        self.context_menu.add_command(label="Open File", command=self.ctx_open_file)
        self.context_menu.add_command(label="Open Location", command=self.ctx_open_location)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="🗑 DELETE FILE", command=self.ctx_delete_file)

    # --- HELPERS ---
    def on_drop(self, event):
        path = event.data
        if path.startswith('{') and path.endswith('}'):
            path = path[1:-1]
        
        if os.path.isfile(path):
            self.load_input_image(path)
        else:
            messagebox.showwarning("Error", "Dropped item is not a file.")

    def block_edit(self, event):
        if (event.state == 4 and event.keysym.lower() == 'c'): return None
        if event.keysym in ("Up", "Down", "Left", "Right", "Home", "End", "Next", "Prior"): return None
        return "break"

    def select_all_text(self, event):
        self.txt_meta.tag_add("sel", "1.0", "end")
        return "break"

    def copy_all_metadata(self):
        text = self.txt_meta.get("1.0", tk.END).strip()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)

    def copy_seed(self):
        path = self.get_selected_path()
        if not path: return

        found_seed = None
        try:
            img = Image.open(path)
            # Automatic1111
            if 'parameters' in img.info:
                match = re.search(r"Seed:\s*(\d+)", img.info['parameters'])
                if match: found_seed = match.group(1)
            
            # ComfyUI
            if not found_seed and 'prompt' in img.info:
                try:
                    data = json.loads(img.info['prompt'])
                    for v in data.values():
                        inputs = v.get('inputs', {})
                        if 'seed' in inputs:
                            found_seed = str(inputs['seed']); break
                        if 'noise_seed' in inputs:
                            found_seed = str(inputs['noise_seed']); break
                except: pass
        except: pass

        if found_seed:
            self.clipboard_clear()
            self.clipboard_append(found_seed)
            messagebox.showinfo("Copied", f"Seed: {found_seed}")
        else:
            messagebox.showwarning("Info", "No Seed found.")

    def open_cache_manager(self):
        CacheManager(self)

    # --- CORE ---
    def browse_image(self):
        path = filedialog.askopenfilename(filetypes=[("Images", "*.jpg *.jpeg *.png *.webp")])
        if path: self.load_input_image(path)

    def paste_clipboard(self):
        try:
            img = ImageGrab.grabclipboard()
            if isinstance(img, Image.Image):
                temp_path = os.path.join(os.getcwd(), "_temp_clipboard.png")
                img.save(temp_path, "PNG")
                self.load_input_image(temp_path)
            elif isinstance(img, list):
                self.load_input_image(img[0])
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def load_input_image(self, path):
        self.input_image_path = path
        try:
            img = Image.open(path)
            img.thumbnail((200, 200))
            self.tk_img = ImageTk.PhotoImage(img)
            self.lbl_preview.config(image=self.tk_img, text="", width=200, height=200)
            self.check_ready()
        except: pass

    def select_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.target_folder = folder
            self.lbl_folder.config(text=folder)
            self.save_config()
            self.check_ready()

    def check_ready(self):
        if self.target_folder and self.input_image_path:
            self.btn_search.config(state=tk.NORMAL)

    def toggle_scan(self):
        if self.scanner_thread and self.scanner_thread.is_alive():
            self.scanner_thread.stop()
            self.btn_search.config(text="Stopping...", state=tk.DISABLED)
        else:
            self.image_cache = []
            for item in self.tree.get_children(): self.tree.delete(item)
            self.txt_meta.delete(1.0, tk.END)
            
            self.scanner_thread = ImageScanner(self.target_folder, self.input_image_path, 
                                             self.result_queue, self.status_queue)
            self.scanner_thread.start()
            self.btn_search.config(text="STOP SCAN", bg="#D32F2F")

    def check_queue(self):
        try:
            while True:
                msg_type, data = self.status_queue.get_nowait()
                if msg_type == "status": self.lbl_status.config(text=data)
                elif msg_type == "progress": self.progress['value'] = data
                elif msg_type == "done": 
                    self.btn_search.config(text="START SCAN", bg=COLOR_ACCENT, state=tk.NORMAL)
                    messagebox.showinfo("Scan Complete", "Finished scanning folder.")
        except queue.Empty: pass

        try:
            while True:
                res = self.result_queue.get_nowait()
                thumb = None
                try:
                    img = Image.open(res['path'])
                    img.thumbnail((50, 50))
                    thumb = ImageTk.PhotoImage(img)
                    self.image_cache.append(thumb)
                except: pass
                
                # Insert item
                self.tree.insert("", "end", text="", image=thumb, 
                                 values=(res['name'], res['distance'], res['size'], res['path']))
        except queue.Empty: pass

        self.after(100, self.check_queue)

    # --- ACTIONS ---
    def on_tree_select(self, event):
        path = self.get_selected_path()
        if path: self.show_metadata(path)

    def show_metadata(self, path):
        output = []
        try:
            img = Image.open(path)
            output.append(f"Format: {img.format} | Size: {img.size} | Mode: {img.mode}\n" + "-"*40)
            
            if img.info:
                for k, v in img.info.items():
                    if k in ['prompt', 'workflow', 'parameters']:
                        try:
                            if isinstance(v, str) and (v.startswith('{') or v.startswith('[')):
                                parsed = json.loads(v)
                                output.append(f"\n[{k}]:\n{json.dumps(parsed, indent=2)}")
                            else:
                                output.append(f"\n[{k}]:\n{v}")
                        except: output.append(f"\n[{k}]:\n{v}")
                    else:
                        output.append(f"[{k}]: {v}")
        except Exception as e: output.append(f"Error: {e}")
        
        self.txt_meta.delete(1.0, tk.END)
        self.txt_meta.insert(tk.END, "\n".join(output))

    def on_double_click(self, event): self.ctx_open_file()
    def show_context_menu(self, event):
        if self.tree.identify_row(event.y):
            self.tree.selection_set(self.tree.identify_row(event.y))
            self.context_menu.tk_popup(event.x_root, event.y_root)

    def get_selected_path(self):
        sel = self.tree.selection()
        if sel: return self.tree.item(sel[0], 'values')[3] # Index 3 is Path
        return None

    def ctx_open_file(self):
        path = self.get_selected_path()
        if path:
            if platform.system() == 'Darwin': subprocess.call(('open', path))
            elif platform.system() == 'Windows': os.startfile(path)
            else: subprocess.call(('xdg-open', path))

    def ctx_open_location(self):
        path = self.get_selected_path()
        if not path: return
        if platform.system() == "Windows":
            subprocess.Popen(['explorer', '/select,', os.path.normpath(path)])
        elif platform.system() == "Darwin":
            subprocess.call(["open", "-R", path])
        else:
            subprocess.Popen(["xdg-open", os.path.dirname(path)])

    def on_delete_key(self, event):
        self.ctx_delete_file()

    def ctx_delete_file(self):
        path = self.get_selected_path()
        selected_item = self.tree.selection()
        
        if path and selected_item:
            confirm = messagebox.askyesno("Confirm Delete", 
                                        f"Are you sure you want to delete:\n{os.path.basename(path)}?\n\nThis cannot be undone.",
                                        icon='warning')
            if confirm:
                try:
                    os.remove(path)
                    self.tree.delete(selected_item)
                    self.lbl_status.config(text=f"Deleted: {os.path.basename(path)}")
                    self.txt_meta.delete(1.0, tk.END)
                except Exception as e:
                    messagebox.showerror("Error", f"Could not delete file: {e}")

if __name__ == "__main__":
    app = App()
    app.mainloop()