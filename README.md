# PP-MITM-Shield
  
**PP-MITM-Shield** is a multi-layer protection tool against Man-in-the-Middle (MITM) attacks  
for Linux systems (tested on Red Hat-based distributions).  
It provides real-time detection and active blocking of suspicious traffic across multiple protocols,  
preventing ARP spoofing, DNS poisoning, DHCP attacks, SSL stripping, ICMP redirects, rogue AP connections,  
and broadcast poisoning.

---

## 🚀 Features

- **Modular Protection Architecture** – Each protection mechanism is implemented as a separate Python module for clarity and maintainability.
- **Real-Time Detection** – Continuous packet inspection using `scapy` with minimal overhead.
- **Automatic Mitigation** – Offending hosts are blocked instantly via `iptables`.
- **Learning Mode** – Allows building **whitelists** of legitimate hosts before enabling protection.
- **Interactive CLI** – Easy-to-use text menu to start individual modules or all at once.
- **Logging & Monitoring** – All alerts and actions are logged for audit and analysis.

---

## 🛡️ Protection Modules

| Module | Protocols / Techniques Covered | Description |
|--------|---------------------------------|-------------|
| **ARP Protection** | ARP | Detects ARP spoofing / poisoning by comparing incoming ARP replies with the trusted table. |
| **DNS Protection** | DNS | Detects forged DNS responses that redirect to malicious IP addresses. |
| **DHCP Protection** | DHCP | Detects rogue DHCP servers trying to assign malicious configurations. |
| **SSL-Strip Detection** | HTTP / HTTPS | Detects attempts to downgrade HTTPS connections to HTTP. |
| **Rogue-AP Detection** | 802.11 / Wi-Fi | Detects unauthorized access points mimicking legitimate SSIDs. |
| **Broadcast-Poison Protection** | LLMNR, NBNS, mDNS, WS-Discovery | Detects spoofed broadcast/multicast name resolutions and service discovery packets. |
| **ICMP Redirect Protection** | ICMP Redirect | Detects and blocks forged ICMP redirect messages attempting to change routing. |
| **HTTPS→HTTP Redirect Watcher** | HTTP 3xx Responses | Detects redirections from secure to insecure protocols. |

---

## 📂 Project Structure


```
PP-MITM-Shield/
│
├── alerts.log                # Main alert log file
├── arp_protect.py             # ARP spoofing detection & blocking
├── blacklist.txt              # List of blacklisted IP/MAC addresses
├── blocks.txt                 # Active firewall block records
├── broadcast_poison.py        # LLMNR/mDNS/NBNS/WSD broadcast spoof detection
├── dhcp_protect.py            # DHCP spoofing detection & blocking
├── dns_protect.py             # DNS spoofing detection & blocking
├── http_redirect_watch.py     # HTTPS→HTTP downgrade detection
├── icmp_redirect_guard.py     # ICMP redirect attack detection
├── learning_menu.py           # Learning mode & list management
├── logs/                      # Directory for additional log files
├── main.py                    # Main interactive menu / module launcher
├── README.md                  # Project documentation
├── rogue_ap.py                # Rogue access point detection
├── ssl_strip_detect.py        # SSL stripping detection
├── whitelist.txt              # List of whitelisted IP/MAC addresses
└── LICENSE                    # License file
```

## 📦 Installation & Dependencies (Red Hat / CentOS / Rocky / AlmaLinux)

PP‑MITM‑Shield requires Python 3 and several libraries/tools to operate.
Below are the tested dependencies and installation commands for Red Hat–based systems.

### 1️⃣ Update system
```bash
sudo dnf update -y
```

### 2️⃣ Install required system packages
```bash
sudo dnf install -y \
  python3 python3-pip \
  iptables iproute \
  git
```
> Notes  
> - On EL8/EL9, `iptables` is the nftables shim and works fine with this project.  
> - SELinux may stay Enforcing; the tool only sniffs traffic and manages host firewall rules.

### 3️⃣ (Recommended) Create a Python virtual environment
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

### 4️⃣ Python libraries
Minimal dependency set is **Scapy**.
```bash
pip install --upgrade scapy
```

If you prefer a requirements file, add:
```text
scapy>=2.5.0
```
and install with:
```bash
pip install -r requirements.txt
```

### 5️⃣ Clone the repository
```bash
git clone https://github.com/Pavel-P09/PP-MITM-Shield.git
cd PP-MITM-Shield
```

### 6️⃣ (Optional) Make scripts executable
```bash
chmod +x *.py
```

### 7️⃣ Run the tool
```bash
sudo python3 main.py
```
> Run with `sudo` to enable raw‑socket capture and automatic firewall blocking.

### 🔧 Optional utilities for lab diagnostics (not required for protection)
```bash
sudo dnf install -y tcpdump
```

### ✅ Verified environment
- OS: Rocky Linux 9 / AlmaLinux 9 / CentOS Stream 9 (EL9)
- Kernel: 5.x (EL9)
- Python: 3.9+


### Menu Structure
1. **Learning / Lists / Firewall / Logs** – Manage whitelists, blacklists, view logs, clear firewall rules.
2. **Protection & Monitoring Modules** – Start/stop individual protections or all at once.
3. **Exit** – Quit the tool.

### Starting All Protections
From the **Protection & Monitoring Modules** menu:
```
[9] Start All Protections
```
You will be prompted for:
- **Interface** – Press Enter for all interfaces or type one (e.g., `enp0s3`).
- **Broadcast-Poison: Monitor ALL UDP ports?** – `y` for all UDP traffic, `n` for standard ports only.

---

## 📑 Logging

- All detections and blocks are logged in `logs/`.
- Each module writes its own log file for easier analysis.
- Logs are plain text and can be rotated or parsed by external tools.

---

## ⚙️ How It Works

1. **Packet Capture** – Each module listens for its protocol(s) using `scapy` BPF filters.
2. **Validation** – Incoming packets are analyzed against learned whitelists and expected patterns.
3. **Detection** – If a packet violates trusted rules, it is flagged as malicious.
4. **Mitigation** – Offender’s IP/MAC is blocked instantly via `iptables`.
5. **Alerting** – Event is logged with timestamp, type, offending host, and mitigation action.

---

## 📌 Notes

- Best used **after learning mode** to avoid blocking legitimate devices.
- Designed for **host-level protection** – does not replace a perimeter firewall.
- All modules can be extended to support new attack vectors.

---

## Network-Wide Deployment

While **PP-MITM-Shield** is currently designed for host-level protection, the same multi-layer MITM defense logic can be deployed network-wide.  
By running lightweight agents on strategically placed VLAN segments or selected network nodes, it is possible to provide centralized monitoring and coordinated blocking for all connected devices.  

Such an architecture would allow scalable protection across the entire infrastructure without the need to install the tool on every single host.  
This extended network-wide version can be developed as a custom solution upon request.


## 📜 License

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

This project is licensed under the [MIT License](LICENSE).

