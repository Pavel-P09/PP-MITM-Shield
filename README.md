# PP-MITM-Shield

**PP-MITM-Shield** is a multi-layered host-level defense system against various forms of **Man-in-the-Middle (MITM)** and network spoofing attacks.  
It is designed for deployment on **Linux** hosts to provide **real-time detection**, **alerting**, and **automatic blocking** of malicious traffic at the firewall level.

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
├── arp_protect.py
├── dns_protect.py
├── dhcp_protect.py
├── ssl_strip_detect.py
├── rogue_ap.py
├── broadcast_poison.py
├── icmp_redirect_guard.py
├── http_redirect_watch.py
├── main.py                # Main menu / module launcher
├── learning_menu.py       # Learning mode & whitelist/blacklist management
├── logs/                  # Alert logs
└── lists/                 # Whitelists / blacklists
```

---

## 🔧 Requirements

- Python **3.8+**
- `scapy`
- `iptables` (Linux only)
- Root privileges (`sudo`) for packet capture and firewall rules

---

## 📥 Installation

```bash
# Clone the repository
git clone https://github.com/Pavel-P09/PP-MITM-Shield.git
cd PP-MITM-Shield

# Install dependencies
pip install -r requirements.txt
```

---

## ▶️ Usage

### Launch Main Menu
```bash
sudo python3 main.py
```

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

## 📜 License

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

This project is licensed under the [MIT License](LICENSE).

