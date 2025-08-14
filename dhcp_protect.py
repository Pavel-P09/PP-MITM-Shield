#!/usr/bin/env python3
import argparse, atexit, os, re, subprocess, threading, time
from pathlib import Path
from typing import Set

from scapy.all import sniff, Ether, IP, DHCP  # type: ignore

BASE   = Path(__file__).resolve().parent
ALERTS = BASE / "alerts.log"
BLOCKS = BASE / "blocks.txt"
WL     = BASE / "whitelist.txt"

RAW_CHAIN = "DHCP_GUARD"
MAC_RE = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", re.I)
MON     = {2: "OFFER", 5: "ACK", 6: "NAK"}

blocked: Set[str] = set()          # MACs already blocked
ALLOW  : Set[str]                  # filled in main()
IFACE  : str                       # filled in main()

# ── helpers ────────────────────────────────────────────────────────────
def sh(cmd: list[str]) -> None:
    subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def log(msg: str) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    with ALERTS.open("a") as f: f.write(f"{ts} | {msg}\n")

def allowed_macs() -> Set[str]:
    if not WL.exists(): return set()
    return {m.group(0).lower()
            for m in (MAC_RE.search(l.split("#", 1)[0])
                      for l in WL.read_text().splitlines()) if m}

# ── preventive raw-table rule (works for broadcast + unicast) ──────────
def install_raw_chain() -> None:
    sh(["iptables", "-t", "raw", "-N", RAW_CHAIN])
    sh(["iptables", "-t", "raw", "-F", RAW_CHAIN])

    for mac in ALLOW:
        sh(["iptables", "-t", "raw", "-A", RAW_CHAIN,
            "-p", "udp", "--sport", "67",
            "-m", "mac", "--mac-source", mac,
            "-j", "RETURN"])

    sh(["iptables", "-t", "raw", "-A", RAW_CHAIN,
        "-p", "udp", "--sport", "67", "-j", "DROP"])

    # ensure first jump
    sh(["iptables", "-t", "raw", "-D", "PREROUTING", "-j", RAW_CHAIN])
    sh(["iptables", "-t", "raw", "-I", "PREROUTING", "1", "-j", RAW_CHAIN])

    def cleanup():
        sh(["iptables", "-t", "raw", "-D", "PREROUTING", "-j", RAW_CHAIN])
        sh(["iptables", "-t", "raw", "-F", RAW_CHAIN])
        sh(["iptables", "-t", "raw", "-X", RAW_CHAIN])
    atexit.register(cleanup)

# ── runtime block + lease reset ────────────────────────────────────────
def add_filter_drop(ip: str, mac: str) -> None:
    for r in (
        ["iptables","-C","INPUT","-m","mac","--mac-source",mac,"-j","DROP"],
        ["iptables","-I","INPUT","-m","mac","--mac-source",mac,"-j","DROP"],
        ["iptables","-C","FORWARD","-m","mac","--mac-source",mac,"-j","DROP"],
        ["iptables","-I","FORWARD","-m","mac","--mac-source",mac,"-j","DROP"],
        ["iptables","-C","INPUT","-s",ip,"-j","DROP"],
        ["iptables","-I","INPUT","-s",ip,"-j","DROP"],
        ["iptables","-C","OUTPUT","-d",ip,"-j","DROP"],
        ["iptables","-I","OUTPUT","-d",ip,"-j","DROP"],
        ["iptables","-C","FORWARD","-s",ip,"-j","DROP"],
        ["iptables","-I","FORWARD","-s",ip,"-j","DROP"],
    ):
        sh(r)
    with BLOCKS.open("a") as f: f.write(f"{ip} {mac}\n")
    blocked.add(mac)

def restart_dhclient() -> None:
    if not IFACE:
        return
    sh(["dhclient", "-r", IFACE])
    sh(["ip", "addr", "flush", "dev", IFACE])
    sh(["dhclient", IFACE])

# ── packet handler (alerts) ────────────────────────────────────────────
def handle(pkt):
    if not pkt.haslayer(DHCP): return
    mac = pkt[Ether].src.lower()
    if mac in ALLOW: return

    opt = next((o for o in pkt[DHCP].options
                if isinstance(o, tuple) and o[0] == "message-type"), None)
    if not opt: return
    code = int(opt[1]) if isinstance(opt[1], (bytes, int)) else int(opt[1][0])
    if code not in MON: return

    ip_src = pkt[IP].src
    msg = f"[ALERT] Rogue DHCP {MON[code]} | IP={ip_src} MAC={mac}"
    if mac in blocked:
        print(msg+" (already blocked)"); log(msg+" (already blocked)"); return

    print(msg); log(msg)
    add_filter_drop(ip_src, mac)
    blk = f"[BLOCKED] {mac} {ip_src}"
    print(blk); log(blk)

    threading.Thread(target=restart_dhclient, daemon=True).start()

# ── main ───────────────────────────────────────────────────────────────
def main() -> None:
    if os.geteuid() != 0:
        print("Run as root."); return
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--iface"); ap.add_argument("--loop", action="store_true")
    args, _ = ap.parse_known_args()

    global ALLOW, IFACE
    ALLOW = allowed_macs()
    IFACE = args.iface or ""

    install_raw_chain()

    print("[DHCP Protection] Running. Ctrl+C to stop.")
    try:
        sniff(filter="udp and (port 67 or 68)", prn=handle,
              store=0, iface=IFACE or None)
    except KeyboardInterrupt:
        print("\n[DHCP Protection] stopped.")

if __name__ == "__main__":
    main()
