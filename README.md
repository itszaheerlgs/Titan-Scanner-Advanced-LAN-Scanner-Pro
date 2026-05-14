# ⚡ Titan Scanner — Advanced LAN Scanner Pro

A powerful, GUI-based network reconnaissance and security auditing tool built with Python and Tkinter. Titan Scanner gives you deep visibility into your local network with a sleek Dracula-themed terminal interface.

---

## ✨ Features

### 🔍 Network Discovery
- **LAN Host Scanner** — Scans a custom IP range using multi-threaded ICMP pings to identify all active hosts.
- **OS Fingerprinting** — Detects likely operating system (Windows, Linux/macOS, or Network Device) via TTL analysis.
- **Hostname & MAC Resolution** — Resolves hostnames via reverse DNS and retrieves MAC addresses from the ARP table.
- **Network Map** — Visual canvas-based topology map drawn after each scan.
- **Available IP Listing** — Lists all unoccupied IPs in the scanned range.

### 🛠️ Per-Host Tools
| Tool | Description |
|---|---|
| **Ping** | Sends a multi-packet ICMP ping sequence and streams results live. |
| **Port Scan** | Checks configurable common ports for open TCP connections and identifies services. |
| **Banner Grab / Vuln Audit** | Grabs service banners on common ports and flags known risks (Telnet, FTP, outdated SSH, RDP). |
| **Bruteforce (Hydra-Lite)** | Tests FTP and HTTP Basic Auth against a list of default credentials. |
| **rDNS / MAC Lookup** | Performs reverse DNS resolution and queries the macvendors.com API for the hardware vendor. |
| **Wake-on-LAN** | Sends a WoL Magic Packet to a target host using its MAC address. |
| **Traceroute** | Runs a system traceroute/tracert and streams each hop in real time. |
| **Latency Monitor** | Continuously pings a target at 1-second intervals and logs round-trip time. |
| **Web Scan** | Probes HTTP/HTTPS, reads server headers, audits for missing security headers (HSTS, CSP, X-Frame-Options, etc.), and fetches `robots.txt`. |

### 🌐 Network-Wide Tools
- **UPnP Deep-Scan** — Sends M-SEARCH multicasts to discover UPnP-enabled devices on the network.
- **Watchdog IDS** — Continuously monitors discovered hosts for offline events and ARP spoofing (MAC address changes), alerting in real time.
- **Live Packet Sniffer** — Binds a raw socket to the local interface and streams packet summaries. Requires Administrator/root privileges.
- **Custom Web Recon** — Scrape and analyze any URL: resolves IP, retrieves headers, parses page title & description, and finds all linked domains.

### 📄 Reporting
- **HTML Audit Report** — Generates a styled, timestamped HTML report of all discovered hosts and opens it in your browser.

---

## 🖥️ Screenshots

> *Add your screenshots here.*

---

## 🚀 Getting Started

### Prerequisites
- Python **3.8+**
- Tkinter (bundled with standard Python on Windows; install `python3-tk` on Linux)
- No third-party pip packages required — uses the standard library only.

### Installation

```bash
git clone https://github.com/your-username/titan-scanner.git
cd titan-scanner
```

### Running

**Windows:**
```bash
python titanScanner.py
```

**Linux / macOS:**
```bash
python3 titanScanner.py
```

> **Note:** Some features (Live Sniffer, raw sockets) require running as **Administrator** (Windows) or **root** (Linux/macOS).

---

## ⚙️ Configuration

Click the **⚙️ SETTINGS** button in the sidebar to adjust:

| Setting | Default | Description |
|---|---|---|
| Max Threads | 50 | Concurrent threads for scanning |
| Ping Timeout | 1.0 s | Timeout per ICMP ping |
| Port Timeout | 0.5 s | Timeout per TCP port probe |
| Common Ports | 21, 22, 23, 80, 139, 443, 445, 3389, 8080 | Comma-separated port list for scans |

You can also set a **custom IP range** directly in the sidebar (e.g. `192.168.1.1-254`).

---

## ⚠️ Disclaimer

Titan Scanner is intended for **authorized use only** on networks you own or have explicit permission to test. Scanning or auditing networks without authorization may be illegal. The authors accept no liability for misuse.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

## 👤 Author

**Dether/Zaheer Lagos**  
I.T NGANI  
GitHub: [itszaheerlgs](https://github.com/itszaheerlgs)
