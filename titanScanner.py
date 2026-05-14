import os
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
import tkinter as tk
from tkinter import scrolledtext, ttk
from tkinter import messagebox
from ipaddress import IPv4Address
import re
import urllib.request
import urllib.parse
import urllib.error
import math
import datetime
import webbrowser
import ftplib
import base64
import ssl

# --- Configuration & Globals ---
THREAD_COUNT = 50
PING_TIMEOUT = 1
PING_PACKET_COUNT = 4
PORT_TIMEOUT = 0.5
COMMON_PORTS = [21, 22, 23, 80, 139, 443, 445, 3389, 8080]

ACTIVE_HOSTS_DATA = {}
available_ips = []
lock = threading.Lock()
TARGET_NETWORK = None
local_ip_address = None
WATCHDOG_RUNNING = False
SNIFFER_RUNNING = False


# --- UI Theme Colors (Dracula Inspired) ---
class Theme:
    BG = "#1E1E2E"  # Main Background
    PANEL_BG = "#282A36"  # Sidebar/Panel Background
    FG = "#F8F8F2"  # Main Text
    MUTED = "#6272A4"  # Muted Text / Borders
    ACCENT = "#BD93F9"  # Purple Accent
    ACCENT_HOVER = "#FF79C6"  # Pink Hover
    SUCCESS = "#50FA7B"  # Green active
    WARNING = "#FFB86C"  # Orange warning
    ERROR = "#FF5555"  # Red error
    TERMINAL_BG = "#000000"  # Pure black for outputs
    TERMINAL_FG = "#50FA7B"  # Hacker green for outputs
    FONT_MAIN = ("Segoe UI", 10)
    FONT_BOLD = ("Segoe UI", 10, "bold")
    FONT_TITLE = ("Segoe UI", 14, "bold")
    FONT_MONO = ("Consolas", 10)


# --- Core Scanner Logic ---

def get_local_network_prefix():
    global local_ip_address
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip_address = s.getsockname()[0]
        s.close()
        return ".".join(local_ip_address.split('.')[:-1]) + '.'
    except Exception:
        return '192.168.1.'


def get_mac_address(ip_address):
    mac = "N/A"
    try:
        kwargs = {}
        if os.name == 'nt':
            kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
            command = f"arp -a {ip_address}"
        else:
            command = f"arp -n {ip_address}"

        output = subprocess.check_output(command, shell=True, text=True, timeout=1, stderr=subprocess.STDOUT, **kwargs)
        mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', output)
        if mac_match:
            mac = mac_match.group(0).lower().replace('-', ':')
    except Exception:
        pass
    return mac


def send_wol(mac_address):
    """Sends a Wake-on-LAN Magic Packet."""
    if not mac_address or mac_address in ["N/A", "Local Machine"]: return
    try:
        mac_hex = mac_address.replace(':', '').replace('-', '')
        if len(mac_hex) != 12: return
        data = bytes.fromhex('FF' * 6 + mac_hex * 16)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(data, ('<broadcast>', 9))
    except Exception:
        pass


def check_host(ip_suffix, target_net=None):
    global TARGET_NETWORK
    if target_net: TARGET_NETWORK = target_net
    ip_address = f"{TARGET_NETWORK}{ip_suffix}"

    if ip_address == local_ip_address:
        with lock:
            ACTIVE_HOSTS_DATA[ip_address] = {'hostname': socket.gethostname(), 'mac': 'Local Machine', 'os': 'Local OS'}
        return

    kwargs = {}
    if os.name == 'nt':
        command = f"ping -n 1 -w {PING_TIMEOUT * 1000} {ip_address}"
        kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
    else:
        command = f"ping -c 1 -W {PING_TIMEOUT} {ip_address}"

    response = subprocess.run(command, shell=True, capture_output=True, text=True, **kwargs)

    if response.returncode == 0:
        hostname = "N/A"
        try:
            socket.setdefaulttimeout(0.5)
            hostname, _, _ = socket.gethostbyaddr(ip_address)
        except Exception:
            pass
        mac = get_mac_address(ip_address)

        ttl_match = re.search(r'[Tt][Tt][Ll]=(\d+)', response.stdout, re.IGNORECASE)
        os_guess = "Unknown"
        if ttl_match:
            ttl = int(ttl_match.group(1))
            if ttl <= 64:
                os_guess = "Linux / macOS"
            elif ttl <= 128:
                os_guess = "Windows"
            else:
                os_guess = "Network Device"

        with lock:
            ACTIVE_HOSTS_DATA[ip_address] = {'hostname': hostname, 'mac': mac, 'os': os_guess}
    else:
        with lock:
            available_ips.append(ip_address)


# --- Animated & Responsive GUI ---

class NetworkScannerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🌐 Advanced LAN Scanner Pro (Titan Edition)")
        self.geometry("1100x820")
        self.minsize(900, 650)
        self.configure(bg=Theme.BG)

        # State variables
        self.is_scanning = False
        self.animation_frame = 0
        self.pulse_id = None
        self.monitor_running = False

        # Settings Variables
        self.thread_var = tk.IntVar(value=THREAD_COUNT)
        self.ping_timeout_var = tk.DoubleVar(value=PING_TIMEOUT)
        self.port_timeout_var = tk.DoubleVar(value=PORT_TIMEOUT)
        self.ports_var = tk.StringVar(value=", ".join(map(str, COMMON_PORTS)))

        self.custom_range_var = tk.StringVar(value=get_local_network_prefix() + "1-254")

        self.setup_styles()
        self.create_layout()

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')

        self.style.configure('Main.TFrame', background=Theme.BG)
        self.style.configure('Panel.TFrame', background=Theme.PANEL_BG)

        self.style.configure('TLabel', background=Theme.BG, foreground=Theme.FG, font=Theme.FONT_MAIN)
        self.style.configure('Panel.TLabel', background=Theme.PANEL_BG, foreground=Theme.FG, font=Theme.FONT_MAIN)
        self.style.configure('Title.TLabel', background=Theme.PANEL_BG, foreground=Theme.ACCENT, font=Theme.FONT_TITLE)

        self.style.configure('Action.TButton', font=Theme.FONT_BOLD, background=Theme.ACCENT, foreground=Theme.BG,
                             borderwidth=0, padding=10)
        self.style.map('Action.TButton', background=[('active', Theme.ACCENT_HOVER), ('disabled', Theme.MUTED)])

        self.style.configure('Tool.TButton', font=("Segoe UI", 9), background=Theme.MUTED, foreground=Theme.FG,
                             borderwidth=0, padding=6)
        self.style.map('Tool.TButton', background=[('active', Theme.ACCENT), ('disabled', Theme.PANEL_BG)])

        self.style.configure('Danger.TButton', font=("Segoe UI", 9), background=Theme.ERROR, foreground=Theme.BG,
                             borderwidth=0, padding=6)
        self.style.map('Danger.TButton', background=[('active', "#FF8888"), ('disabled', Theme.PANEL_BG)])

        self.style.configure('TProgressbar', thickness=6, background=Theme.SUCCESS, troughcolor=Theme.PANEL_BG,
                             bordercolor=Theme.BG)

        self.style.configure('TNotebook', background=Theme.BG, borderwidth=0)
        self.style.configure('TNotebook.Tab', background=Theme.PANEL_BG, foreground=Theme.FG, padding=[15, 5],
                             font=Theme.FONT_MAIN, borderwidth=0)
        self.style.map('TNotebook.Tab', background=[('selected', Theme.ACCENT)], foreground=[('selected', Theme.BG)])

    def create_layout(self):
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)

        # --- Sidebar (Left Panel) ---
        self.sidebar = ttk.Frame(self, style='Panel.TFrame', padding=20)
        self.sidebar.grid(row=0, column=0, sticky="nsew")

        ttk.Label(self.sidebar, text="⚡ NET SCANNER", style='Title.TLabel').pack(pady=(0, 15))

        ttk.Label(self.sidebar, text="Target Range:", style='Panel.TLabel').pack(anchor='w')
        self.range_entry = ttk.Entry(self.sidebar, textvariable=self.custom_range_var, font=Theme.FONT_MAIN)
        self.range_entry.pack(fill='x', pady=(0, 10))

        self.scan_btn = ttk.Button(self.sidebar, text="🚀 START SCAN", style='Action.TButton',
                                   command=self.start_scan_thread)
        self.scan_btn.pack(fill='x', pady=5)

        self.report_btn = ttk.Button(self.sidebar, text="📄 Generate HTML Report", style='Tool.TButton',
                                     command=self.generate_html_report, state=tk.DISABLED)
        self.report_btn.pack(fill='x', pady=5)

        self.settings_btn = ttk.Button(self.sidebar, text="⚙️ SETTINGS", style='Tool.TButton',
                                       command=self.open_settings)
        self.settings_btn.pack(fill='x', pady=5)

        ttk.Separator(self.sidebar, orient='horizontal').pack(fill='x', pady=15)

        ttk.Label(self.sidebar, text="Target IP Tools", style='Panel.TLabel', font=Theme.FONT_BOLD).pack(anchor='w',
                                                                                                         pady=(0, 5))

        self.ip_combo_var = tk.StringVar()
        self.ip_combobox = ttk.Combobox(self.sidebar, textvariable=self.ip_combo_var, state='readonly',
                                        font=Theme.FONT_MAIN)
        self.ip_combobox.pack(fill='x', pady=5)
        self.ip_combobox['values'] = ["Run a scan first..."]
        self.ip_combobox.set("Run a scan first...")

        # --- TACTICAL GRID FOR ADVANCED TOOLS ---
        tools_grid = ttk.Frame(self.sidebar, style='Panel.TFrame')
        tools_grid.pack(fill='x', pady=5)
        tools_grid.columnconfigure(0, weight=1)
        tools_grid.columnconfigure(1, weight=1)

        self.ping_btn = ttk.Button(tools_grid, text="▶️ Ping", style='Tool.TButton', command=self.start_ping,
                                   state=tk.DISABLED)
        self.ping_btn.grid(row=0, column=0, sticky="ew", padx=2, pady=2)

        self.port_btn = ttk.Button(tools_grid, text="🔌 Port Scan", style='Tool.TButton', command=self.start_port_scan,
                                   state=tk.DISABLED)
        self.port_btn.grid(row=0, column=1, sticky="ew", padx=2, pady=2)

        self.audit_btn = ttk.Button(tools_grid, text="🛡️ Banner Grab", style='Danger.TButton',
                                    command=self.start_vuln_audit, state=tk.DISABLED)
        self.audit_btn.grid(row=1, column=0, sticky="ew", padx=2, pady=2)

        self.brute_btn = ttk.Button(tools_grid, text="🪓 Bruteforce", style='Danger.TButton',
                                    command=self.start_bruteforce, state=tk.DISABLED)
        self.brute_btn.grid(row=1, column=1, sticky="ew", padx=2, pady=2)

        self.lookup_btn = ttk.Button(tools_grid, text="🔍 rDNS/MAC", style='Tool.TButton', command=self.start_lookup,
                                     state=tk.DISABLED)
        self.lookup_btn.grid(row=2, column=0, sticky="ew", padx=2, pady=2)

        self.trace_btn = ttk.Button(tools_grid, text="🛤️ Traceroute", style='Tool.TButton',
                                    command=self.start_traceroute, state=tk.DISABLED)
        self.trace_btn.grid(row=2, column=1, sticky="ew", padx=2, pady=2)

        self.wol_btn = ttk.Button(tools_grid, text="🪄 WoL", style='Tool.TButton', command=self.start_wol,
                                  state=tk.DISABLED)
        self.wol_btn.grid(row=3, column=0, sticky="ew", padx=2, pady=2)

        self.monitor_btn = ttk.Button(tools_grid, text="📈 Latency Mon", style='Tool.TButton',
                                      command=self.toggle_monitor,
                                      state=tk.DISABLED)
        self.monitor_btn.grid(row=3, column=1, sticky="ew", padx=2, pady=2)

        self.web_btn = ttk.Button(tools_grid, text="🕸️ Web Scan", style='Tool.TButton', command=self.start_web_scan,
                                  state=tk.DISABLED)
        self.web_btn.grid(row=4, column=0, columnspan=2, sticky="ew", padx=2, pady=2)

        ttk.Separator(self.sidebar, orient='horizontal').pack(fill='x', pady=15)
        ttk.Label(self.sidebar, text="Network-Wide Tools", style='Panel.TLabel', font=Theme.FONT_BOLD).pack(anchor='w',
                                                                                                            pady=(0, 5))

        self.upnp_btn = ttk.Button(self.sidebar, text="🌐 UPnP Deep-Scan", style='Tool.TButton',
                                   command=self.start_upnp_scan)
        self.upnp_btn.pack(fill='x', pady=2)

        self.watchdog_btn = ttk.Button(self.sidebar, text="👁️ Start Watchdog IDS", style='Tool.TButton',
                                       command=self.toggle_watchdog, state=tk.DISABLED)
        self.watchdog_btn.pack(fill='x', pady=2)

        self.sniffer_btn = ttk.Button(self.sidebar, text="📡 Live Sniffer (Admin)", style='Tool.TButton',
                                      command=self.toggle_sniffer)
        self.sniffer_btn.pack(fill='x', pady=2)

        # --- CUSTOM WEB RECON FEATURE ---
        ttk.Separator(self.sidebar, orient='horizontal').pack(fill='x', pady=15)
        ttk.Label(self.sidebar, text="Custom Web Recon", style='Panel.TLabel', font=Theme.FONT_BOLD).pack(anchor='w',
                                                                                                          pady=(0, 5))

        self.custom_url_var = tk.StringVar(value="https://")
        self.url_entry = ttk.Entry(self.sidebar, textvariable=self.custom_url_var, font=Theme.FONT_MAIN)
        self.url_entry.pack(fill='x', pady=(0, 5))

        self.custom_web_btn = ttk.Button(self.sidebar, text="🌍 Scrape & Analyze URL", style='Tool.TButton',
                                         command=self.start_custom_web_scan)
        self.custom_web_btn.pack(fill='x', pady=2)

        # Bind hover cursors
        buttons = [self.scan_btn, self.report_btn, self.settings_btn, self.ping_btn, self.port_btn,
                   self.audit_btn, self.brute_btn, self.lookup_btn, self.wol_btn, self.trace_btn, self.monitor_btn,
                   self.web_btn, self.upnp_btn, self.watchdog_btn, self.sniffer_btn, self.custom_web_btn]
        for btn in buttons:
            btn.bind("<Enter>", lambda e, b=btn: b.config(cursor="hand2") if str(b['state']) != 'disabled' else None)
            btn.bind("<Leave>", lambda e, b=btn: b.config(cursor=""))

        # --- Main Content (Right Panel) ---
        self.main_panel = ttk.Frame(self, style='Main.TFrame', padding=20)
        self.main_panel.grid(row=0, column=1, sticky="nsew")
        self.main_panel.columnconfigure(0, weight=1)
        self.main_panel.rowconfigure(2, weight=1)

        self.status_var = tk.StringVar(value="IDLE - Ready to scan.")
        self.status_lbl = tk.Label(self.main_panel, textvariable=self.status_var, bg=Theme.BG, fg=Theme.MUTED,
                                   font=("Segoe UI", 12, "italic"))
        self.status_lbl.grid(row=0, column=0, sticky="w", pady=(0, 10))

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.main_panel, variable=self.progress_var, maximum=100,
                                            style='TProgressbar')
        self.progress_bar.grid(row=1, column=0, sticky="ew", pady=(0, 15))

        self.notebook = ttk.Notebook(self.main_panel)
        self.notebook.grid(row=2, column=0, sticky="nsew")

        # Tabs
        self.tab_active = ttk.Frame(self.notebook, style='Main.TFrame')
        self.notebook.add(self.tab_active, text='🟢 Active Hosts')
        self.active_text = self.create_terminal(self.tab_active)

        self.tab_map = ttk.Frame(self.notebook, style='Main.TFrame')
        self.notebook.add(self.tab_map, text='🗺️ Network Map')
        self.map_canvas = tk.Canvas(self.tab_map, bg=Theme.TERMINAL_BG, highlightthickness=0)
        self.map_canvas.pack(fill='both', expand=True, padx=10, pady=10)
        self.map_canvas.bind("<Configure>", self.on_canvas_resize)

        self.tab_avail = ttk.Frame(self.notebook, style='Main.TFrame')
        self.notebook.add(self.tab_avail, text='🆓 Available IPs')
        self.avail_text = self.create_terminal(self.tab_avail)

        self.tab_tools = ttk.Frame(self.notebook, style='Main.TFrame')
        self.notebook.add(self.tab_tools, text='💻 Terminal Output')
        self.tools_text = self.create_terminal(self.tab_tools)

        self.tab_dev = ttk.Frame(self.notebook, style='Main.TFrame')
        self.notebook.add(self.tab_dev, text='👨‍💻 Dev Info')
        self.dev_text = self.create_terminal(self.tab_dev)
        self.animate_typewriter(self.dev_text,
                                "\n\n\t=================================\n\t🌐 Advanced LAN Scanner Pro\n\n\tDeveloped By:\n\tDether S. Lagos : Zaheer\n\n\tVersion: 4.4 (Titan Web Explorer Edition)\n\t=================================\n")

    def create_terminal(self, parent):
        text_widget = scrolledtext.ScrolledText(
            parent, bg=Theme.TERMINAL_BG, fg=Theme.TERMINAL_FG,
            font=Theme.FONT_MONO, insertbackground=Theme.FG,
            relief="flat", padx=10, pady=10, state='disabled'
        )
        text_widget.pack(expand=True, fill='both')
        return text_widget

    # --- Animations & Canvas Drawing ---

    def pulse_status(self):
        if not self.is_scanning:
            self.status_lbl.config(fg=Theme.SUCCESS)
            return
        colors = [Theme.ACCENT, Theme.ACCENT_HOVER, Theme.FG, Theme.ACCENT_HOVER]
        self.status_lbl.config(fg=colors[self.animation_frame % len(colors)])
        self.animation_frame += 1
        self.pulse_id = self.after(150, self.pulse_status)

    def animate_typewriter(self, widget, text, index=0):
        if index == 0:
            widget.config(state='normal')
            widget.delete('1.0', tk.END)
        if index < len(text):
            widget.insert(tk.END, text[index])
            widget.see(tk.END)
            self.after(5, self.animate_typewriter, widget, text, index + 1)  # Sped up for large outputs
        else:
            widget.config(state='disabled')

    def append_terminal(self, widget, text):
        widget.config(state='normal')
        widget.insert(tk.END, text)
        widget.see(tk.END)
        widget.config(state='disabled')

    def on_canvas_resize(self, event):
        if ACTIVE_HOSTS_DATA:
            self.draw_network_map()

    def draw_network_map(self):
        self.map_canvas.delete("all")
        width = self.map_canvas.winfo_width()
        height = self.map_canvas.winfo_height()
        if width <= 10 or height <= 10: return

        cx, cy = width / 2, height / 2
        radius = min(width, height) / 2.5

        # Draw Central Router/Local Machine
        self.map_canvas.create_oval(cx - 30, cy - 30, cx + 30, cy + 30, fill=Theme.ACCENT, outline=Theme.FG, width=2)
        self.map_canvas.create_text(cx, cy + 45, text="Local Gateway", fill=Theme.FG, font=Theme.FONT_BOLD)

        ips = sorted(ACTIVE_HOSTS_DATA.keys(), key=IPv4Address)
        num_hosts = len(ips)

        for i, ip in enumerate(ips):
            angle = i * (2 * math.pi / num_hosts) if num_hosts > 0 else 0
            x = cx + radius * math.cos(angle)
            y = cy + radius * math.sin(angle)

            # Draw connecting line
            self.map_canvas.create_line(cx, cy, x, y, fill=Theme.MUTED, dash=(4, 2))

            # Draw Host Node
            node_color = Theme.SUCCESS if ACTIVE_HOSTS_DATA[ip].get('os') != "Network Device" else Theme.WARNING
            self.map_canvas.create_oval(x - 15, y - 15, x + 15, y + 15, fill=node_color, outline=Theme.BG, width=2)

            # Host labels
            hostname = ACTIVE_HOSTS_DATA[ip].get('hostname', 'Unknown')
            label = f"{ip}\n{hostname[:12]}"
            self.map_canvas.create_text(x, y + 25, text=label, fill=Theme.TERMINAL_FG, font=("Consolas", 8),
                                        justify="center")

    # --- Core Scan Execution ---

    def start_scan_thread(self):
        self.is_scanning = True
        self.scan_btn.config(state=tk.DISABLED, text="⏳ SCANNING...")
        for btn in [self.ping_btn, self.port_btn, self.audit_btn, self.brute_btn, self.lookup_btn, self.report_btn,
                    self.trace_btn, self.wol_btn, self.monitor_btn, self.web_btn]:
            btn.config(state=tk.DISABLED)
        self.progress_var.set(0)
        self.notebook.select(self.tab_active)

        self.active_text.config(state='normal')
        self.active_text.delete('1.0', tk.END)
        self.active_text.insert(tk.END, "Initializing network scan engines...\n")
        self.active_text.config(state='disabled')

        self.animation_frame = 0
        self.pulse_status()
        threading.Thread(target=self.scan_network, daemon=True).start()

    def scan_network(self):
        global ACTIVE_HOSTS_DATA, available_ips, TARGET_NETWORK
        ACTIVE_HOSTS_DATA.clear()
        available_ips = []

        range_input = self.custom_range_var.get().strip()
        try:
            if "-" in range_input:
                base_ip = ".".join(range_input.split('.')[:-1]) + "."
                start_suffix, end_suffix = map(int, range_input.split('.')[-1].split('-'))
                TARGET_NETWORK = base_ip
                ip_suffixes = list(range(start_suffix, end_suffix + 1))
            else:
                TARGET_NETWORK = get_local_network_prefix()
                ip_suffixes = list(range(1, 255))
        except Exception:
            TARGET_NETWORK = get_local_network_prefix()
            ip_suffixes = list(range(1, 255))

        self.after(0, lambda: self.status_var.set(
            f"Scanning range: {TARGET_NETWORK}{ip_suffixes[0]} to {TARGET_NETWORK}{ip_suffixes[-1]} ..."))
        start_time = time.time()

        with ThreadPoolExecutor(max_workers=self.thread_var.get()) as executor:
            futures = {executor.submit(check_host, i, TARGET_NETWORK): i for i in ip_suffixes}
            completed = 0
            for future in as_completed(futures):
                completed += 1
                progress = (completed / len(ip_suffixes)) * 100
                self.after(0, self.progress_var.set, progress)

        end_time = time.time()
        self.is_scanning = False
        self.after(0, self.finalize_scan, end_time - start_time)

    def finalize_scan(self, duration):
        if self.pulse_id:
            self.after_cancel(self.pulse_id)

        self.status_var.set(f"Scan complete in {duration:.2f} seconds.")
        self.status_lbl.config(fg=Theme.SUCCESS)
        self.scan_btn.config(state=tk.NORMAL, text="🚀 START SCAN")

        sorted_ips = sorted(ACTIVE_HOSTS_DATA.keys(), key=IPv4Address)

        # Output Table
        output_str = f"Found {len(sorted_ips)} Active Hosts on network {TARGET_NETWORK}0\n"
        output_str += "=" * 105 + "\n"
        output_str += f"| {'IP Address':<15} | {'PC Name':<28} | {'MAC Address':<18} | {'Detected OS':<22} |\n"
        output_str += "|" + "-" * 17 + "|" + "-" * 30 + "|" + "-" * 20 + "|" + "-" * 24 + "|\n"

        for ip in sorted_ips:
            data = ACTIVE_HOSTS_DATA[ip]
            output_str += f"| {ip:<15} | {data['hostname']:<28} | {data['mac']:<18} | {data['os']:<22} |\n"

        output_str += "=" * 105 + "\n"
        self.animate_typewriter(self.active_text, output_str)
        self.after(500, self.draw_network_map)

        # Available IPs
        sorted_avail = sorted(available_ips, key=IPv4Address)
        avail_str = f"Found {len(sorted_avail)} Available IPs:\n" + "-" * 50 + "\n"
        for i in range(0, len(sorted_avail), 5):
            avail_str += " ".join(f"{ip:<15}" for ip in sorted_avail[i:i + 5]) + "\n"
        self.after(800, self.animate_typewriter, self.avail_text, avail_str)

        if sorted_ips:
            self.ip_combobox['values'] = sorted_ips
            self.ip_combobox.set(sorted_ips[0])
            for btn in [self.ping_btn, self.port_btn, self.audit_btn, self.brute_btn, self.lookup_btn, self.wol_btn,
                        self.trace_btn, self.watchdog_btn, self.report_btn, self.monitor_btn, self.web_btn]:
                btn.config(state=tk.NORMAL)
        else:
            self.ip_combobox['values'] = ["No hosts found"]
            self.ip_combobox.set("No hosts found")

    # --- Enterprise Reporting ---

    def generate_html_report(self):
        if not ACTIVE_HOSTS_DATA: return

        filename = f"Network_Audit_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Security Audit</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f7f6; color: #333; margin: 40px; }}
                h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.2); }}
                th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #3498db; color: white; text-transform: uppercase; font-size: 14px; }}
                tr:hover {{ background-color: #f1f1f1; }}
                .summary {{ background: #fff; padding: 20px; border-radius: 5px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 20px; }}
            </style>
        </head>
        <body>
            <h1>🌐 Network Security Audit Report</h1>
            <div class="summary">
                <p><strong>Scan Date:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Target Network:</strong> {TARGET_NETWORK}0/24</p>
                <p><strong>Total Active Hosts:</strong> {len(ACTIVE_HOSTS_DATA)}</p>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Hostname</th>
                        <th>MAC Address</th>
                        <th>Guessed OS</th>
                    </tr>
                </thead>
                <tbody>
        """
        for ip in sorted(ACTIVE_HOSTS_DATA.keys(), key=IPv4Address):
            data = ACTIVE_HOSTS_DATA[ip]
            html_content += f"<tr><td>{ip}</td><td>{data.get('hostname', 'N/A')}</td><td>{data.get('mac', 'N/A')}</td><td>{data.get('os', 'N/A')}</td></tr>"

        html_content += """
                </tbody>
            </table>
        </body>
        </html>
        """

        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            webbrowser.open('file://' + os.path.realpath(filename))
            self.status_var.set(f"Report saved and opened: {filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to write report: {e}")

    # --- Tool Integration ---
    def prepare_tool(self, tool_name):
        target = self.ip_combo_var.get()
        if not target or target in ["Run a scan first...", "No hosts found"]:
            messagebox.showwarning("Warning", "Select a valid IP target first.")
            return None

        self.notebook.select(self.tab_tools)
        self.animate_typewriter(self.tools_text, f"\n> Starting {tool_name} on {target}...\n> Please wait...\n\n")
        return target

    def start_ping(self):
        target = self.prepare_tool("Ping sequence")
        if not target: return
        threading.Thread(target=self.run_ping, args=(target,), daemon=True).start()

    def run_ping(self, target):
        command = f"ping -n {PING_PACKET_COUNT} {target}" if os.name == 'nt' else f"ping -c {PING_PACKET_COUNT} {target}"
        kwargs = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {}

        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                       **kwargs)
            for line in process.stdout:
                self.after(0, self.append_terminal, self.tools_text, f"  {line}")
                time.sleep(0.05)
        except Exception as e:
            self.after(0, self.append_terminal, self.tools_text, f"\n[!] Ping error: {e}\n")

        self.after(0, self.append_terminal, self.tools_text, "\n> Ping complete.\n")

    def toggle_monitor(self):
        target = self.ip_combo_var.get()
        if not target or target in ["Run a scan first...", "No hosts found"]:
            messagebox.showwarning("Warning", "Select a valid IP target first.")
            return

        self.monitor_running = not self.monitor_running

        if self.monitor_running:
            self.monitor_btn.config(text="🛑 Stop Monitor", style='Danger.TButton')
            self.notebook.select(self.tab_tools)
            self.animate_typewriter(self.tools_text,
                                    f"\n> Initiating Continuous Latency Monitor for {target}...\n> Throttling: 1 ICMP Request / Second\n\n")
            threading.Thread(target=self.monitor_loop, args=(target,), daemon=True).start()
        else:
            self.monitor_btn.config(text="📈 Latency Mon", style='Tool.TButton')
            self.append_terminal(self.tools_text, "\n> Latency Monitor Stopped.\n")

    def monitor_loop(self, target):
        while self.monitor_running:
            kwargs = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {}
            cmd = f"ping -n 1 -w {int(PING_TIMEOUT * 1000)} {target}" if os.name == 'nt' else f"ping -c 1 -W {PING_TIMEOUT} {target}"

            start_time = time.time()
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, **kwargs)

            timestamp = datetime.datetime.now().strftime("%H:%M:%S")

            if res.returncode == 0:
                time_match = re.search(r'time[=|<]([0-9.]+)ms', res.stdout, re.IGNORECASE)
                if time_match:
                    latency = f"{time_match.group(1)} ms"
                    self.after(0, self.append_terminal, self.tools_text,
                               f"  [{timestamp}] Reply from {target}: time={latency}\n")
                else:
                    self.after(0, self.append_terminal, self.tools_text,
                               f"  [{timestamp}] Reply from {target}: time < 1ms\n")
            else:
                self.after(0, self.append_terminal, self.tools_text,
                           f"  [{timestamp}] Request timed out or host unreachable.\n")

            # Calculate remaining sleep time to maintain exactly 1 request per second
            elapsed = time.time() - start_time
            sleep_time = max(0, 1.0 - elapsed)
            time.sleep(sleep_time)

    def start_port_scan(self):
        target = self.prepare_tool("Port Scan")
        if not target: return
        self.progress_var.set(0)
        threading.Thread(target=self.run_port_scan, args=(target,), daemon=True).start()

    def run_port_scan(self, target):
        open_ports = []
        ports = COMMON_PORTS
        timeout = self.port_timeout_var.get()

        def check_port(p):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    if s.connect_ex((target, p)) == 0:
                        try:
                            svc = socket.getservbyport(p, "tcp")
                        except OSError:
                            svc = "unknown"
                        return p, svc
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=self.thread_var.get()) as executor:
            futures = {executor.submit(check_port, p): p for p in ports}
            for i, future in enumerate(as_completed(futures), 1):
                res = future.result()
                if res:
                    open_ports.append(res)
                    self.after(0, self.append_terminal, self.tools_text,
                               f"  [+] Port {res[0]:<5} is OPEN  (Service: {res[1]})\n")
                self.after(0, self.progress_var.set, (i / len(ports)) * 100)

        summary = f"\n> Scan finished. {len(open_ports)} open ports found out of {len(ports)} scanned.\n"
        self.after(0, self.append_terminal, self.tools_text, summary)

    # --- Enterprise Auditing (Banner Grabbing) ---
    def start_vuln_audit(self):
        target = self.prepare_tool("Vulnerability Audit")
        if not target: return
        self.progress_var.set(0)
        threading.Thread(target=self.run_vuln_audit, args=(target,), daemon=True).start()

    def run_vuln_audit(self, target):
        timeout = self.port_timeout_var.get()
        audit_ports = [21, 22, 23, 80, 443, 3306, 3389]

        self.after(0, self.append_terminal, self.tools_text,
                   "  [*] Probing common vulnerable ports & grabbing banners...\n\n")

        for p in audit_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    if s.connect_ex((target, p)) == 0:
                        banner = "No Banner / Blocked"
                        vuln_warning = ""

                        try:
                            if p in [80, 443]:
                                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                            else:
                                s.sendall(b"\r\n")

                            recv_data = s.recv(1024).decode('utf-8', errors='ignore').strip()
                            if recv_data:
                                banner = recv_data.split('\n')[0][:50]
                        except Exception:
                            pass

                        if p == 21: vuln_warning = "⚠️ FTP is unencrypted. Susceptible to packet sniffing."
                        if p == 23: vuln_warning = "🚨 CRITICAL: Telnet is open! Cleartext credentials risk."
                        if p == 3389: vuln_warning = "⚠️ RDP open. Ensure strong passwords & Network Level Auth."
                        if "OpenSSH" in banner and "7." in banner: vuln_warning = "⚠️ Outdated OpenSSH version detected."

                        output = f"  [+] Port {p} OPEN\n      Banner: {banner}\n"
                        if vuln_warning: output += f"      {vuln_warning}\n"
                        output += "\n"
                        self.after(0, self.append_terminal, self.tools_text, output)
            except Exception:
                pass

        self.after(0, self.append_terminal, self.tools_text, "> Audit Complete.\n")

    # --- Credential Bruteforcer (Hydra-Lite) ---
    def start_bruteforce(self):
        target = self.prepare_tool("Default Credential Bruteforcer")
        if not target: return
        threading.Thread(target=self.run_bruteforce, args=(target,), daemon=True).start()

    def run_bruteforce(self, target):
        creds_to_test = [
            ('admin', 'admin'), ('root', 'root'), ('admin', 'password'),
            ('admin', ''), ('user', 'user'), ('anonymous', 'anonymous')
        ]

        # 1. Test FTP (Port 21)
        self.after(0, self.append_terminal, self.tools_text, f"  [*] Scanning {target} for open FTP...\n")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.port_timeout_var.get())
                if s.connect_ex((target, 21)) == 0:
                    self.after(0, self.append_terminal, self.tools_text,
                               "  [!] FTP OPEN. Executing dictionary attack...\n")
                    success = False
                    for u, p in creds_to_test:
                        try:
                            ftp = ftplib.FTP()
                            ftp.connect(target, 21, timeout=3)
                            ftp.login(u, p)
                            self.after(0, self.append_terminal, self.tools_text,
                                       f"  [🚨] VULNERABILITY FOUND: FTP Access Granted!\n       Username: '{u}' | Password: '{p}'\n")
                            ftp.quit()
                            success = True
                            break
                        except Exception:
                            pass
                    if not success:
                        self.after(0, self.append_terminal, self.tools_text,
                                   "  [-] FTP Secure: Default credentials failed.\n")
        except Exception:
            pass

        # 2. Test HTTP Basic Auth (Port 80)
        self.after(0, self.append_terminal, self.tools_text, f"  [*] Scanning {target} for HTTP Basic Auth...\n")
        try:
            # Check if Auth is required
            req = urllib.request.Request(f"http://{target}/")
            try:
                urllib.request.urlopen(req, timeout=2)
                requires_auth = False
            except urllib.error.HTTPError as e:
                requires_auth = (e.code == 401 and 'Basic' in e.headers.get('WWW-Authenticate', ''))
            except Exception:
                requires_auth = False

            if requires_auth:
                self.after(0, self.append_terminal, self.tools_text,
                           "  [!] HTTP Basic Auth Detected. Executing dictionary attack...\n")
                success = False
                for u, p in creds_to_test:
                    auth_str = base64.b64encode(f"{u}:{p}".encode()).decode()
                    req = urllib.request.Request(f"http://{target}/")
                    req.add_header("Authorization", f"Basic {auth_str}")
                    try:
                        urllib.request.urlopen(req, timeout=2)
                        # If we get here without a 401, it worked!
                        self.after(0, self.append_terminal, self.tools_text,
                                   f"  [🚨] VULNERABILITY FOUND: HTTP Access Granted!\n       Username: '{u}' | Password: '{p}'\n")
                        success = True
                        break
                    except urllib.error.HTTPError as e:
                        if e.code != 401:
                            # 403 or 404 means login worked but page is restricted/missing
                            self.after(0, self.append_terminal, self.tools_text,
                                       f"  [🚨] VULNERABILITY FOUND: HTTP Auth Passed (Returned {e.code})!\n       Username: '{u}' | Password: '{p}'\n")
                            success = True
                            break
                    except Exception:
                        pass

                if not success:
                    self.after(0, self.append_terminal, self.tools_text,
                               "  [-] HTTP Secure: Default credentials failed.\n")
            else:
                self.after(0, self.append_terminal, self.tools_text, "  [-] No HTTP Basic Auth portal detected.\n")

        except Exception:
            pass

        self.after(0, self.append_terminal, self.tools_text, "\n> Bruteforce module finished.\n")

    # --- Web Scanning Feature ---
    def start_web_scan(self):
        target = self.prepare_tool("Web Scanner (HTTP/HTTPS)")
        if not target: return
        threading.Thread(target=self.run_web_scan, args=(target,), daemon=True).start()

    def run_web_scan(self, target):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # Ignore self-signed certificates common on local devices

        protocols = ['http', 'https']
        for proto in protocols:
            url = f"{proto}://{target}/"
            self.after(0, self.append_terminal, self.tools_text, f"  [*] Probing {url}...\n")

            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
                response = urllib.request.urlopen(req, timeout=3, context=ctx if proto == 'https' else None)
                status = response.getcode()
                headers = response.info()

                self.after(0, self.append_terminal, self.tools_text, f"  [+] Status: {status} OK\n")

                # Parse interesting Server details
                server = headers.get('Server', 'Hidden/Unknown')
                powered_by = headers.get('X-Powered-By', 'Hidden/Unknown')
                self.after(0, self.append_terminal, self.tools_text, f"      Server: {server}\n")
                if powered_by != 'Hidden/Unknown':
                    self.after(0, self.append_terminal, self.tools_text, f"      X-Powered-By: {powered_by}\n")

                # Perform a Security Header Audit
                sec_headers = {
                    'Strict-Transport-Security': 'HSTS',
                    'X-Frame-Options': 'Clickjacking Protection',
                    'Content-Security-Policy': 'CSP',
                    'X-Content-Type-Options': 'MIME Sniffing Protection'
                }

                self.after(0, self.append_terminal, self.tools_text, "      Security Headers Audit:\n")
                for h, desc in sec_headers.items():
                    if h in headers:
                        self.after(0, self.append_terminal, self.tools_text, f"        [✔] {desc} ({h}) is PRESENT\n")
                    else:
                        self.after(0, self.append_terminal, self.tools_text, f"        [!] {desc} ({h}) is MISSING\n")

                # Attempt to probe for hidden robots.txt
                robots_url = f"{url}robots.txt"
                try:
                    r_req = urllib.request.Request(robots_url, headers={'User-Agent': 'Mozilla/5.0'})
                    r_resp = urllib.request.urlopen(r_req, timeout=2, context=ctx if proto == 'https' else None)
                    if r_resp.getcode() == 200:
                        self.after(0, self.append_terminal, self.tools_text,
                                   f"      [+] Found Web Indexing File: {robots_url}\n")
                except:
                    pass

            except urllib.error.HTTPError as e:
                self.after(0, self.append_terminal, self.tools_text, f"  [-] Status: {e.code} ({e.reason})\n")
            except urllib.error.URLError as e:
                self.after(0, self.append_terminal, self.tools_text, f"  [-] Failed to connect: {e.reason}\n")
            except Exception as e:
                self.after(0, self.append_terminal, self.tools_text, f"  [-] Error: {e}\n")

            self.after(0, self.append_terminal, self.tools_text, "\n")

        self.after(0, self.append_terminal, self.tools_text, "> Web Scan Complete.\n")

    # --- Custom Web Recon Feature ---
    def start_custom_web_scan(self):
        target_url = self.custom_url_var.get().strip()
        if not target_url or target_url == "https://":
            messagebox.showwarning("Warning", "Please enter a valid target URL.")
            return

        # Ensure scheme is present
        if not target_url.startswith('http'):
            target_url = 'https://' + target_url

        self.notebook.select(self.tab_tools)
        self.animate_typewriter(self.tools_text,
                                f"\n> Starting Custom Web Recon on {target_url}...\n> Please wait...\n\n")
        threading.Thread(target=self.run_custom_web_scan, args=(target_url,), daemon=True).start()

    def run_custom_web_scan(self, target_url):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            # 1. IP Resolution
            parsed_url = urllib.parse.urlparse(target_url)
            domain = parsed_url.netloc
            self.after(0, self.append_terminal, self.tools_text, f"  [*] Resolving {domain}...\n")
            try:
                ip = socket.gethostbyname(domain)
                self.after(0, self.append_terminal, self.tools_text, f"  [+] IP Address: {ip}\n")
            except Exception as e:
                self.after(0, self.append_terminal, self.tools_text, f"  [-] Failed to resolve IP: {e}\n")

            # 2. HTTP Request & Scrape
            self.after(0, self.append_terminal, self.tools_text, f"  [*] Sending HTTP Request to {target_url}...\n")
            req = urllib.request.Request(target_url,
                                         headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Titan/4.4'})

            start_time = time.time()
            response = urllib.request.urlopen(req, timeout=5, context=ctx)
            end_time = time.time()

            status = response.getcode()
            headers = response.info()
            html_body = response.read().decode('utf-8', errors='ignore')

            self.after(0, self.append_terminal, self.tools_text,
                       f"  [+] Status: {status} OK (Response Time: {((end_time - start_time) * 1000):.2f}ms)\n")

            # 3. Analyze Headers
            server = headers.get('Server', 'Hidden/Unknown')
            self.after(0, self.append_terminal, self.tools_text, f"      Server: {server}\n")

            # 4. Scrape Page Info
            title_match = re.search(r'<title>(.*?)</title>', html_body, re.IGNORECASE)
            page_title = title_match.group(1).strip() if title_match else "No Title Found"

            self.after(0, self.append_terminal, self.tools_text, f"      Page Title: {page_title}\n")
            self.after(0, self.append_terminal, self.tools_text, f"      Page Size: {len(html_body)} bytes\n")

            # Simple form & script counts
            form_count = len(re.findall(r'<form', html_body, re.IGNORECASE))
            self.after(0, self.append_terminal, self.tools_text,
                       f"      Forms Found: {form_count} (Possible entry points)\n")

            script_count = len(re.findall(r'<script', html_body, re.IGNORECASE))
            self.after(0, self.append_terminal, self.tools_text, f"      Scripts Found: {script_count}\n")

            # Content Snippet Display
            clean_body = re.sub(r'<[^>]+>', ' ', html_body)  # Strip HTML tags
            clean_body = ' '.join(clean_body.split())  # Collapse whitespace
            snippet = clean_body[:200] + "..." if len(clean_body) > 200 else clean_body
            self.after(0, self.append_terminal, self.tools_text, f"\n  [*] Content Snippet:\n      \"{snippet}\"\n")

        except urllib.error.HTTPError as e:
            self.after(0, self.append_terminal, self.tools_text, f"  [-] HTTP Error: {e.code} ({e.reason})\n")
        except urllib.error.URLError as e:
            self.after(0, self.append_terminal, self.tools_text, f"  [-] URL Error: Failed to connect: {e.reason}\n")
        except Exception as e:
            self.after(0, self.append_terminal, self.tools_text, f"  [-] Error: {e}\n")

        self.after(0, self.append_terminal, self.tools_text, "\n> Custom Web Recon Complete.\n")

    # --- UPnP/SSDP Router Deep Scan ---
    def start_upnp_scan(self):
        self.notebook.select(self.tab_tools)
        self.animate_typewriter(self.tools_text,
                                "\n> Initiating UPnP / SSDP Subnet Broadcast...\n> Forcing hidden devices to reveal internal XML configs...\n\n")
        threading.Thread(target=self.run_upnp_scan, daemon=True).start()

    def run_upnp_scan(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.settimeout(4)

            # SSDP M-SEARCH Magic Packet
            msg = \
                'M-SEARCH * HTTP/1.1\r\n' \
                'HOST: 239.255.255.250:1900\r\n' \
                'MAN: "ssdp:discover"\r\n' \
                'MX: 2\r\n' \
                'ST: upnp:rootdevice\r\n' \
                '\r\n'

            sock.sendto(msg.encode('utf-8'), ('239.255.255.250', 1900))

            devices_found = 0
            while True:
                try:
                    data, addr = sock.recvfrom(65536)
                    devices_found += 1
                    response = data.decode('utf-8', errors='ignore')

                    server = re.search(r'(?i)Server:\s*(.+)', response)
                    location = re.search(r'(?i)Location:\s*(.+)', response)

                    self.after(0, self.append_terminal, self.tools_text, f"  [+] Device Responded at {addr[0]}:\n")
                    if server:
                        self.after(0, self.append_terminal, self.tools_text,
                                   f"      Software : {server.group(1).strip()}\n")
                    if location:
                        self.after(0, self.append_terminal, self.tools_text,
                                   f"      XML Config: {location.group(1).strip()}\n")
                    self.after(0, self.append_terminal, self.tools_text, "\n")
                except socket.timeout:
                    break

            if devices_found == 0:
                self.after(0, self.append_terminal, self.tools_text,
                           "  [-] No UPnP-enabled devices responded to the broadcast.\n")

        except Exception as e:
            self.after(0, self.append_terminal, self.tools_text, f"  [!] UPnP Error: {e}\n")

        self.after(0, self.append_terminal, self.tools_text, "> UPnP Scan Complete.\n")

    def start_lookup(self):
        target = self.prepare_tool("Advanced Lookup")
        if not target: return
        threading.Thread(target=self.run_lookup, args=(target,), daemon=True).start()

    def run_lookup(self, target):
        self.after(0, self.append_terminal, self.tools_text, f"  [*] Querying Reverse DNS for {target}...\n")
        try:
            socket.setdefaulttimeout(1.0)
            hostname, aliases, _ = socket.gethostbyaddr(target)
            self.after(0, self.append_terminal, self.tools_text, f"  [+] Hostname: {hostname}\n")
            if aliases:
                self.after(0, self.append_terminal, self.tools_text, f"  [+] Aliases : {', '.join(aliases)}\n")
        except Exception:
            self.after(0, self.append_terminal, self.tools_text, "  [-] rDNS    : N/A (No record found)\n")

        mac = ACTIVE_HOSTS_DATA.get(target, {}).get('mac', 'Unknown')
        self.after(0, self.append_terminal, self.tools_text, f"  [+] MAC Addr: {mac}\n")

        self.after(0, self.append_terminal, self.tools_text, "  [*] Querying MAC Vendor API...\n")
        vendor = "Unknown / Not Found"
        if mac not in ["N/A", "Unknown", "Local Machine"]:
            try:
                url = f"https://api.macvendors.com/{urllib.parse.quote(mac)}"
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=3) as response:
                    vendor = response.read().decode('utf-8')
            except Exception:
                vendor = "Rate Limited / API Unreachable"

        self.after(0, self.append_terminal, self.tools_text, f"  [+] Vendor  : {vendor}\n\n> Lookup complete.\n")

    def start_wol(self):
        target = self.prepare_tool("Wake-on-LAN")
        if not target: return
        mac = ACTIVE_HOSTS_DATA.get(target, {}).get('mac', 'N/A')
        if mac in ["N/A", "Local Machine", "Unknown"]:
            self.append_terminal(self.tools_text, "  [!] Error: Invalid MAC Address for WoL.\n")
            return

        self.append_terminal(self.tools_text, f"  [*] Sending Magic Packet to {mac}...\n")
        send_wol(mac)
        self.append_terminal(self.tools_text,
                             "  [+] Magic Packet sent! If BIOS supports WoL, it is booting up.\n\n> WoL complete.\n")

    def start_traceroute(self):
        target = self.prepare_tool("Traceroute")
        if not target: return
        threading.Thread(target=self.run_traceroute, args=(target,), daemon=True).start()

    def run_traceroute(self, target):
        command = f"tracert -d {target}" if os.name == 'nt' else f"traceroute -n {target}"
        kwargs = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {}

        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                       **kwargs)
            for line in process.stdout:
                self.after(0, self.append_terminal, self.tools_text, f"  {line}")
                time.sleep(0.05)
        except Exception as e:
            self.after(0, self.append_terminal, self.tools_text, f"\n[!] Traceroute error: {e}\n")

        self.after(0, self.append_terminal, self.tools_text, "\n> Traceroute complete.\n")

    # --- Intrusion Detection System (IDS) Watchdog ---
    def toggle_watchdog(self):
        global WATCHDOG_RUNNING
        WATCHDOG_RUNNING = not WATCHDOG_RUNNING

        if WATCHDOG_RUNNING:
            self.watchdog_btn.config(text="🛑 Stop Watchdog IDS", style='Action.TButton')
            self.status_var.set("IDS Active: Monitoring for ARP Spoofing & offline hosts...")
            self.status_lbl.config(fg=Theme.WARNING)
            threading.Thread(target=self.watchdog_loop, daemon=True).start()
        else:
            self.watchdog_btn.config(text="👁️ Start Watchdog IDS", style='Tool.TButton')
            self.status_var.set("Watchdog IDS Stopped.")
            self.status_lbl.config(fg=Theme.MUTED)

    def watchdog_loop(self):
        global WATCHDOG_RUNNING, ACTIVE_HOSTS_DATA
        self.after(0, self.notebook.select, self.tab_tools)
        self.after(0, self.append_terminal, self.tools_text,
                   "\n> [IDS WATCHDOG] Started continuous monitoring...\n> Watching for offline devices and MITM (ARP Spoofing) attempts.\n\n")

        # Create a deep copy to establish baseline known MACs
        known_baseline = {ip: data.copy() for ip, data in ACTIVE_HOSTS_DATA.items() if
                          data.get('mac') not in ['N/A', 'Unknown']}

        while WATCHDOG_RUNNING:
            for ip in list(known_baseline.keys()):
                if not WATCHDOG_RUNNING: break

                # 1. Ping Check (Offline Detection)
                kwargs = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {}
                cmd = f"ping -n 1 -w {PING_TIMEOUT * 1000} {ip}" if os.name == 'nt' else f"ping -c 1 -W {PING_TIMEOUT} {ip}"
                res = subprocess.run(cmd, shell=True, capture_output=True, **kwargs)

                if res.returncode != 0:
                    self.after(0, self.append_terminal, self.tools_text, f"  [⚠️ ALERT] Host {ip} went OFFLINE!\n")
                    del known_baseline[ip]
                    continue

                # 2. MAC Integrity Check (ARP Spoofing Detection)
                current_mac = get_mac_address(ip)
                baseline_mac = known_baseline[ip]['mac']

                # If a valid MAC address has suddenly changed, someone is spoofing it
                if current_mac not in ["N/A", "Unknown"] and current_mac != baseline_mac:
                    alert_msg = (
                        f"\n  [🚨 CRITICAL MITM ALERT] ARP SPOOFING DETECTED!\n"
                        f"      IP Address    : {ip}\n"
                        f"      Original MAC  : {baseline_mac}\n"
                        f"      New Spoofed MAC: {current_mac}\n"
                        f"      Someone is attempting to intercept traffic for this IP!\n\n"
                    )
                    self.after(0, self.append_terminal, self.tools_text, alert_msg)
                    # Update baseline to prevent infinite spam, but keep alerting if it changes again
                    known_baseline[ip]['mac'] = current_mac

            time.sleep(5)  # Throttle to avoid flooding the network

    def toggle_sniffer(self):
        global SNIFFER_RUNNING
        SNIFFER_RUNNING = not SNIFFER_RUNNING

        if SNIFFER_RUNNING:
            self.sniffer_btn.config(text="🛑 Stop Sniffer", style='Action.TButton')
            self.notebook.select(self.tab_tools)
            self.animate_typewriter(self.tools_text,
                                    "\n> Attempting to bind Raw Socket for Sniffing...\n> (Requires Administrator/Root privileges)\n\n")
            threading.Thread(target=self.sniffer_loop, daemon=True).start()
        else:
            self.sniffer_btn.config(text="📡 Live Sniffer (Admin)", style='Tool.TButton')
            self.append_terminal(self.tools_text, "\n> Sniffer Stopped.\n")

    def sniffer_loop(self):
        global SNIFFER_RUNNING
        try:
            if os.name == 'nt':
                sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sniffer.bind((local_ip_address, 0))
                sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

            self.after(0, self.append_terminal, self.tools_text,
                       "  [+] Hooked into interface successfully. Listening...\n\n")

            while SNIFFER_RUNNING:
                raw_data, _ = sniffer.recvfrom(65536)
                hex_summary = raw_data[:16].hex(' ')
                self.after(0, self.append_terminal, self.tools_text,
                           f"  [PACKET] Len: {len(raw_data)} | {hex_summary}...\n")
                time.sleep(0.1)

        except PermissionError:
            self.after(0, self.append_terminal, self.tools_text,
                       "  [!] PERMISSION DENIED: You must run this script as Administrator/Root to use raw sockets!\n")
            self.after(0, self.toggle_sniffer)
        except Exception as e:
            self.after(0, self.append_terminal, self.tools_text, f"  [!] Socket Error: {e}\n")
            self.after(0, self.toggle_sniffer)
        finally:
            if os.name == 'nt' and 'sniffer' in locals() and hasattr(sniffer, 'ioctl'):
                try:
                    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except:
                    pass

    # --- Settings Window ---
    def open_settings(self):
        win = tk.Toplevel(self)
        win.title("Settings")
        win.geometry("400x350")
        win.configure(bg=Theme.BG)
        win.transient(self)
        win.grab_set()

        frame = ttk.Frame(win, style='Main.TFrame', padding=20)
        frame.pack(fill='both', expand=True)

        ttk.Label(frame, text="⚙️ Configuration", style='Title.TLabel', background=Theme.BG).pack(pady=(0, 20))

        def make_entry(lbl_text, var):
            f = ttk.Frame(frame, style='Main.TFrame')
            f.pack(fill='x', pady=5)
            ttk.Label(f, text=lbl_text, width=20).pack(side='left')
            e = ttk.Entry(f, textvariable=var, font=Theme.FONT_MAIN)
            e.pack(side='left', fill='x', expand=True)

        make_entry("Max Threads:", self.thread_var)
        make_entry("Ping Timeout (s):", self.ping_timeout_var)
        make_entry("Port Timeout (s):", self.port_timeout_var)
        make_entry("Common Ports (CSV):", self.ports_var)

        btn = ttk.Button(frame, text="Apply & Close", style='Action.TButton', command=lambda: self.apply_settings(win))
        btn.pack(pady=30, fill='x')

    def apply_settings(self, win):
        global THREAD_COUNT, PING_TIMEOUT, PORT_TIMEOUT, COMMON_PORTS
        try:
            THREAD_COUNT = self.thread_var.get()
            PING_TIMEOUT = self.ping_timeout_var.get()
            PORT_TIMEOUT = self.port_timeout_var.get()
            ports = [int(p.strip()) for p in self.ports_var.get().split(',') if p.strip().isdigit()]
            if ports: COMMON_PORTS = ports
            win.destroy()
        except ValueError:
            messagebox.showerror("Error", "Invalid numeric values entered.", parent=win)


if __name__ == '__main__':
    if os.name == 'nt':
        os.environ['COMSPEC'] = 'cmd.exe'

    app = NetworkScannerGUI()
    app.mainloop()