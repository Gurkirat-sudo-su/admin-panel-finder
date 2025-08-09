import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import requests
import threading
import os
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

# Disable InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_PATHS = [
    "admin", "administrator", "admin1", "admin2", "admin/login", "cpanel",
    "adminpanel", "controlpanel", "admin_area", "cms", "manage", "manager",
    "login", "dashboard", "user", "users", "secure", "webadmin", "adm", "panel",
    "backend", "auth", "moderator", "member", "staff", "private", "sysadmin",
    "siteadmin", "access", "admin_home", "control", "data", "config"
]


class BlackTurtleFinder:
    def __init__(self, master):
        self.master = master
        self.master.title("🐢 Black Turtle — Admin Panel Finder")
        self.master.geometry("1100x650")
        self.master.minsize(900, 520)
        self.master.configure(bg="#0e0e0e")

        # State
        self.stop_flag = False
        self.paths_file = None
        self.total_paths = 0
        self.checked_paths = 0
        self.found_count = 0
        self.redirect_count = 0
        self.other_count = 0

        self._create_styles()
        self._create_banner()
        self._create_controls()
        self._create_table()
        self._create_statusbar()

        self.master.bind("<Control-Return>", lambda e: self.start_scan())

    def _create_styles(self):
        style = ttk.Style(self.master)
        style.theme_use("clam")

        style.configure("Treeview",
                        background="#121212",
                        foreground="#e0e0e0",
                        fieldbackground="#121212",
                        rowheight=28,
                        font=("Consolas", 10))
        style.configure("Treeview.Heading",
                        background="#1f1f1f",
                        foreground="#00ffaa",
                        font=("Segoe UI", 11, "bold"))
        style.configure("Horizontal.TProgressbar",
                        troughcolor="#1a1a1a",
                        background="#00ffaa",
                        thickness=12)

    def _create_banner(self):
        self.banner = tk.Canvas(self.master, height=100, highlightthickness=0)
        self.banner.pack(fill="x", side="top")
        self._draw_gradient(self.banner, "#000000", "#004d4d")

        self.banner.create_text(30, 30, anchor="w",
                                text="🐢 Black Turtle",
                                font=("Segoe UI", 26, "bold"),
                                fill="#00ffaa")
        self.banner.create_text(30, 65, anchor="w",
                                text="Fast Multi-threaded Admin Panel Scanner",
                                font=("Segoe UI", 11),
                                fill="#66ffcc")

    def _draw_gradient(self, canvas, color1, color2):
        canvas.update_idletasks()
        width = max(800, canvas.winfo_width())
        steps = 100
        r1, g1, b1 = self._hex_to_rgb(color1)
        r2, g2, b2 = self._hex_to_rgb(color2)
        for i in range(steps):
            r = int(r1 + (r2 - r1) * i / steps)
            g = int(g1 + (g2 - g1) * i / steps)
            b = int(b1 + (b2 - b1) * i / steps)
            color = f"#{r:02x}{g:02x}{b:02x}"
            x0 = (i / steps) * width
            x1 = ((i + 1) / steps) * width
            canvas.create_rectangle(x0, 0, x1, 100, outline="", fill=color)

    @staticmethod
    def _hex_to_rgb(hexcol):
        h = hexcol.lstrip("#")
        return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))

    def _create_controls(self):
        ctrl_frame = tk.Frame(self.master, bg="#0e0e0e", pady=10)
        ctrl_frame.pack(fill="x", padx=16)

        tk.Label(ctrl_frame, text="Target URL", bg="#0e0e0e", fg="#00ffaa",
                 font=("Segoe UI", 10)).grid(row=0, column=0, sticky="w", padx=(6, 6))

        self.url_entry = tk.Entry(ctrl_frame, font=("Segoe UI", 11), width=54,
                                  bg="#1a1a1a", fg="#ffffff",
                                  insertbackground="#ffffff", relief="flat")
        self.url_entry.grid(row=1, column=0, padx=(6, 6), sticky="w")

        word_frame = tk.Frame(ctrl_frame, bg="#0e0e0e")
        word_frame.grid(row=1, column=1, padx=10, sticky="w")

        self.btn_browse = tk.Button(word_frame, text="📂 Browse Wordlist", command=self.browse_file,
                                    bg="#008080", fg="white", relief="flat", padx=12, pady=6)
        self.btn_browse.pack(side="left", padx=(0, 8))

        self.btn_remove_wordlist = tk.Button(word_frame, text="❌ Remove Wordlist",
                                             command=self.remove_wordlist, bg="#993333", fg="white",
                                             relief="flat", padx=12, pady=6, state=tk.DISABLED)
        self.btn_remove_wordlist.pack(side="left")

        scan_frame = tk.Frame(ctrl_frame, bg="#0e0e0e")
        scan_frame.grid(row=1, column=2, padx=10, sticky="e")

        self.btn_start = tk.Button(scan_frame, text="▶ Start Scan", command=self.start_scan,
                                   bg="#00b894", fg="#0b0b0b", relief="flat", padx=18, pady=8)
        self.btn_start.pack(side="left", padx=(0, 8))

        self.btn_stop = tk.Button(scan_frame, text="⏹ Stop Scan", command=self.stop_scan,
                                   bg="#ff7675", fg="#0b0b0b", relief="flat", padx=18, pady=8)
        self.btn_stop.pack(side="left")

        cframe = tk.Frame(ctrl_frame, bg="#0e0e0e")
        cframe.grid(row=0, column=2, sticky="ne", padx=10)
        tk.Label(cframe, text="Concurrency:", bg="#0e0e0e", fg="#00ffaa",
                 font=("Segoe UI", 9)).pack(anchor="e")
        self.concurrency_var = tk.IntVar(value=50)
        self.concurrency_spin = tk.Spinbox(cframe, from_=1, to=200, width=4,
                                           textvariable=self.concurrency_var,
                                           font=("Segoe UI", 10), bg="#1a1a1a",
                                           fg="#ffffff", relief="flat",
                                           insertbackground="#ffffff")
        self.concurrency_spin.pack(anchor="e", pady=4)

    def _create_table(self):
        content_frame = tk.Frame(self.master, bg="#0e0e0e")
        content_frame.pack(fill="both", expand=True, padx=16, pady=(6, 6))

        columns = ("status", "url", "info")
        self.tree = ttk.Treeview(content_frame, columns=columns, show="headings")
        self.tree.heading("status", text="Status")
        self.tree.heading("url", text="URL")
        self.tree.heading("info", text="Info")

        self.tree.column("status", width=120, anchor="center")
        self.tree.column("url", width=600, anchor="w")
        self.tree.column("info", width=240, anchor="w")

        ysb = ttk.Scrollbar(content_frame, orient="vertical", command=self.tree.yview)
        xsb = ttk.Scrollbar(content_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscroll=ysb.set, xscroll=xsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew", columnspan=2)

        content_frame.rowconfigure(0, weight=1)
        content_frame.columnconfigure(0, weight=1)

        self.tree.tag_configure("found", background="#003333", foreground="#00ffaa")
        self.tree.tag_configure("redirect", background="#332b00", foreground="#ffd27a")
        self.tree.tag_configure("other", background="#330000", foreground="#ff9fa8")
        self.tree.tag_configure("neutral", background="#1a1a1a", foreground="#dcdcdc")

        self.tree.bind("<Double-1>", self._on_item_double_click)

    def _create_statusbar(self):
        status_frame = tk.Frame(self.master, bg="#000000", height=44)
        status_frame.pack(fill="x", side="bottom")

        self.status_label = tk.Label(status_frame, text="Idle", bg="#000000", fg="#00ffaa",
                                     font=("Segoe UI", 10))
        self.status_label.pack(side="left", padx=12)

        self.progress = ttk.Progressbar(status_frame, style="Horizontal.TProgressbar",
                                        orient="horizontal", mode="determinate", length=420)
        self.progress.pack(side="right", padx=12, pady=6)

        self.counts_label = tk.Label(status_frame, text="Found: 0  Redirects: 0  Other: 0",
                                     bg="#000000", fg="#00ffaa", font=("Segoe UI", 10))
        self.counts_label.pack(side="right", padx=12)

    def browse_file(self):
        file_path = filedialog.askopenfilename(title="Select wordlist", filetypes=[("Text Files", "*.txt")])
        if file_path:
            self.paths_file = file_path
            self.btn_remove_wordlist.config(state=tk.NORMAL)
            messagebox.showinfo("Wordlist loaded", f"Loaded wordlist: {os.path.basename(file_path)}")

    def remove_wordlist(self):
        self.paths_file = None
        self.btn_remove_wordlist.configure(state=tk.DISABLED)
        messagebox.showinfo("Wordlist removed", "Using default built-in keywords.")

    def start_scan(self):
        target_url = self.url_entry.get().strip()
        if not target_url.startswith(("http://", "https://")):
            messagebox.showerror("Error", "Enter a valid URL starting with http:// or https://")
            return

        self.stop_flag = False
        self.tree.delete(*self.tree.get_children())
        self.checked_paths = self.found_count = self.redirect_count = self.other_count = 0
        self.counts_label.config(text="Found: 0  Redirects: 0  Other: 0")
        self.progress.config(value=0)

        if self.paths_file:
            try:
                with open(self.paths_file, "r", encoding="utf-8", errors="ignore") as f:
                    paths = [line.strip() for line in f if line.strip()]
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {e}")
                return
        else:
            paths = DEFAULT_PATHS[:]

        if not paths:
            messagebox.showerror("Error", "No paths to scan.")
            return

        self.total_paths = len(paths)
        self.progress.config(maximum=self.total_paths)
        self.status_label.config(text=f"Scanning: 0 / {self.total_paths}")

        threading.Thread(target=self._scan_worker, args=(target_url, paths), daemon=True).start()

    def stop_scan(self):
        self.stop_flag = True
        self.status_label.config(text="Stopping scan...")

    def _scan_worker(self, target_url, paths):
        session = requests.Session()
        session.headers.update({"User-Agent": "Mozilla/5.0 (BlackTurtle/2.0)"})
        session.verify = False

        def check_path(path):
            if self.stop_flag:
                return None
            url = f"{target_url.rstrip('/')}/{path.lstrip('/')}"
            try:
                r = session.head(url, timeout=4, allow_redirects=False, stream=True)
                return (r.status_code, url)
            except requests.exceptions.Timeout:
                return ("TIMEOUT", url)
            except Exception:
                return ("ERROR", url)

        max_workers = max(1, int(self.concurrency_var.get()))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(check_path, p): p for p in paths}
            for future in as_completed(futures):
                if self.stop_flag:
                    break
                res = future.result()
                if res:
                    self.master.after(0, lambda c=res[0], u=res[1]: self._handle_result(c, u))

        self.master.after(0, lambda: self.status_label.config(
            text="Scan stopped." if self.stop_flag else "Scan completed."))

    def _handle_result(self, code, url):
        self.checked_paths += 1
        tag = "neutral"
        status_text = str(code)

        if code == 200:
            tag, status_text, self.found_count = "found", "200 OK", self.found_count + 1
        elif code in (301, 302, 303, 307, 308):
            tag, status_text, self.redirect_count = "redirect", f"{code} Redirect", self.redirect_count + 1
        elif code in ("TIMEOUT", "ERROR"):
            tag, status_text, self.other_count = "other", code, self.other_count + 1
        else:
            tag, status_text, self.other_count = "other", f"{code}", self.other_count + 1

        if tag == "found":
            self.tree.insert("", 0, values=(status_text, url, ""), tags=(tag,))
        else:
            self.tree.insert("", "end", values=(status_text, url, ""), tags=(tag,))

        self.counts_label.config(text=f"Found: {self.found_count}  Redirects: {self.redirect_count}  Other: {self.other_count}")
        self.progress['value'] = self.checked_paths
        self.status_label.config(text=f"Scanning: {self.checked_paths} / {self.total_paths}")

    def _on_item_double_click(self, event):
        selected = self.tree.focus()
        if selected:
            vals = self.tree.item(selected, "values")
            if vals and vals[1].startswith(("http://", "https://")):
                webbrowser.open(vals[1])


if __name__ == "__main__":
    root = tk.Tk()
    app = BlackTurtleFinder(root)
    root.mainloop()

