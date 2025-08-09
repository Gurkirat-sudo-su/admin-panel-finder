import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import requests
import threading
import os
import webbrowser

DEFAULT_PATHS = [
    "admin", "administrator", "admin1", "admin2", "admin/login", "cpanel",
    "adminpanel", "controlpanel", "admin_area", "cms", "manage", "manager",
    "login", "dashboard", "user", "users", "secure", "webadmin", "adm", "panel",
    "backend", "auth", "moderator", "member", "staff", "private", "sysadmin",
    "siteadmin", "access", "admin_home", "control", "data", "config"
]

class AdminPanelFinder:
    def __init__(self, master):
        self.master = master
        self.master.title("Admin Panel Finder GUI")
        self.master.geometry("1050x600")

        self.stop_flag = False
        self.paths_file = None

        # Target URL
        tk.Label(master, text="Target URL:", font=("Segoe UI", 11, "bold")).pack()
        self.url_entry = tk.Entry(master, width=80, font=("Segoe UI", 10))
        self.url_entry.pack(pady=5)

        # Wordlist buttons
        btn_wordlist_frame = tk.Frame(master)
        btn_wordlist_frame.pack(pady=5)
        tk.Button(btn_wordlist_frame, text="Browse Wordlist", command=self.browse_file,
                  bg="blue", fg="white", width=20).grid(row=0, column=0, padx=5)
        self.remove_wordlist_btn = tk.Button(btn_wordlist_frame, text="Remove Wordlist",
                                             command=self.remove_wordlist, bg="orange",
                                             fg="white", width=20, state=tk.DISABLED)
        self.remove_wordlist_btn.grid(row=0, column=1, padx=5)

        tk.Label(master, text="Optional: Leave empty to use built-in keywords", fg="gray").pack()

        # Start / Stop
        btn_frame = tk.Frame(master)
        btn_frame.pack(pady=5)
        tk.Button(btn_frame, text="Start Scan", command=self.start_scan,
                  bg="green", fg="white", width=20).grid(row=0, column=0, padx=5)
        tk.Button(btn_frame, text="Stop Scan", command=self.stop_scan,
                  bg="red", fg="white", width=20).grid(row=0, column=1, padx=5)

        # Results table
        columns = ("found", "redirect", "other")
        self.tree = ttk.Treeview(master, columns=columns, show="headings", height=20)

        self.tree.heading("found", text="200 - Found")
        self.tree.heading("redirect", text="302 / 501 - Redirect/Error")
        self.tree.heading("other", text="Other Status Codes")

        # Style
        style = ttk.Style()
        style.configure("Treeview.Heading", font=("Segoe UI", 12, "bold"))
        style.configure("Treeview", font=("Segoe UI", 10), rowheight=28)

        self.tree.column("found", width=350, anchor="w")
        self.tree.column("redirect", width=350, anchor="w")
        self.tree.column("other", width=350, anchor="w")

        # Scrollbar
        scrollbar = ttk.Scrollbar(master, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Row colors
        self.tree.tag_configure("found_tag", background="#d4edda", foreground="#155724")     # Green
        self.tree.tag_configure("redirect_tag", background="#fff3cd", foreground="#856404")  # Yellow
        self.tree.tag_configure("other_tag", background="#f8d7da", foreground="#721c24")     # Red

        # Bind click to open link
        self.tree.bind("<Double-1>", self.open_link)

    def browse_file(self):
        file_path = filedialog.askopenfilename(title="Select paths.txt", filetypes=[("Text Files", "*.txt")])
        if file_path:
            self.paths_file = file_path
            self.remove_wordlist_btn.config(state=tk.NORMAL)
            messagebox.showinfo("File Loaded", f"Loaded wordlist: {os.path.basename(file_path)}")

    def remove_wordlist(self):
        self.paths_file = None
        self.remove_wordlist_btn.config(state=tk.DISABLED)
        messagebox.showinfo("Wordlist Removed", "Custom wordlist removed. Using default keywords.")

    def start_scan(self):
        target_url = self.url_entry.get().strip()
        if not target_url.startswith("http"):
            messagebox.showerror("Error", "Enter a valid URL (http or https)")
            return

        self.stop_flag = False
        self.tree.delete(*self.tree.get_children())  # Clear results
        threading.Thread(target=self.scan, args=(target_url,), daemon=True).start()

    def stop_scan(self):
        self.stop_flag = True
        messagebox.showinfo("Stopped", "Scan stopped by user.")

    def scan(self, target_url):
        if self.paths_file:
            try:
                with open(self.paths_file, "r") as f:
                    paths = [line.strip() for line in f if line.strip()]
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {e}")
                return
        else:
            paths = DEFAULT_PATHS

        for path in paths:
            if self.stop_flag:
                break

            url = f"{target_url.rstrip('/')}/{path.lstrip('/')}"
            try:
                r = requests.get(url, timeout=10)
                if r.status_code == 200:
                    self.tree.insert("", 0, values=(url, "", ""), tags=("found_tag",))
                    self.tree.yview_moveto(0)  # Scroll to top
                    self.master.after(1500, lambda: self.tree.yview_moveto(1))  # Scroll back down
                elif r.status_code in (302, 501):
                    self.tree.insert("", tk.END, values=("", url, ""), tags=("redirect_tag",))
                    self.tree.yview_moveto(1)  # Auto-scroll to bottom
                else:
                    self.tree.insert("", tk.END, values=("", "", f"{r.status_code} - {url}"), tags=("other_tag",))
                    self.tree.yview_moveto(1)
            except requests.exceptions.Timeout:
                self.tree.insert("", tk.END, values=("", "", f"TIMEOUT - {url}"), tags=("other_tag",))
                self.tree.yview_moveto(1)
            except Exception:
                self.tree.insert("", tk.END, values=("", "", f"ERROR - {url}"), tags=("other_tag",))
                self.tree.yview_moveto(1)

    def open_link(self, event):
        selected_item = self.tree.focus()
        if not selected_item:
            return
        values = self.tree.item(selected_item, "values")
        for val in values:
            if val.startswith("http"):
                webbrowser.open(val)
                break

if __name__ == "__main__":
    root = tk.Tk()
    app = AdminPanelFinder(root)
    root.mainloop()
