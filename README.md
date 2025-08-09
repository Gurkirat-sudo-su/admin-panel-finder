
# Admin Panel Finder GUI

A Python-based GUI tool to find potential admin panels on websites using built-in keywords or a custom wordlist.  
Created by **Gurkirat Singh**.

## Features
- Built-in default keyword list
- Option to load and remove a custom wordlist
- Color-coded results (green for found, yellow for redirects, red for errors)
- Clickable links (double-click to open in browser)
- Auto-scrolling results
- GUI built with Tkinter

## Installation (Kali Linux / Linux / Windows)

### 1. Clone the Repository
```bash
git clone https://github.com/Gurkirat-sudo-su/admin-panel-finder.git
cd admin-panel-finder
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

## Usage

Run the tool:
```bash
python admin_panel_finder.py
```

1. Enter the target website URL (must start with `http` or `https`).
2. (Optional) Load a custom wordlist.
3. Click **Start Scan** to begin.
4. Double-click on a found link to open in your browser.

## License
This project is licensed under the [MIT License](LICENSE) © 2025 Gurkirat Singh.
