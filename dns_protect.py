#!/usr/bin/env python3
"""
DNS anti-spoofing module for PP-MultiShield

Key features
------------
* Trusted resolvers = union of whitelist.txt and nameservers from /etc/resolv.conf.
* Internal addresses (192.168.0.0/16) require IP + MAC match; external addresses require IP only.
* Duplicate-safe iptables insertion (-C … || -I …).
* Unified logging to alerts.log.
"""

import argparse
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path
import ipaddress

from scapy.all import sniff, Ether, IP, UDP, DNS  # type: ignore

# ───────── paths ─────────
BASE_DIR   = Path(__file__).resolve().parent
ALERT_LOG  = BASE_DIR / "alerts.log"
WHITELIST  = BASE_DIR / "whitelist.txt"
BLOCKS     = BASE_DIR / "blocks.txt"

# ───────── constants ─────────
INTERNAL_NETS = ["192.168.0.0/16"]

IP_RE  = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
MAC_RE = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")

MONITOR_FILTER = "udp port 53"

# ───────── helpers ─────────
_now = lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_alert(msg: str) -> None:
    with ALERT_LOG.open("a") as f:
        f.write(f"{_now()} | {msg}\n")


def _load_pairs(path: Path):
    """Return set of (ip, mac_or_None) tuples from list file."""
    pairs = set()
    if not path.exists():
        return pairs
    for raw in path.read_text().splitlines():
        raw = raw.split("#", 1)[0].strip()
        if not raw:
            continue
        parts = raw.split()
        ip = parts[0]
        mac = parts[1].lower() if len(parts) > 1 else None
        if IP_RE.fullmatch(ip) and (mac is None or MAC_RE.fullmatch(mac)):
            pairs.add((ip, mac))
    return pairs


read_whitelist = lambda: _load_pairs(WHITELIST)
read_blocks    = lambda: _load_pairs(BLOCKS)


def resolv_conf_ips():
    """Return set of IPs from nameserver lines."""
    ips = set()
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                if line.startswith("nameserver"):
                    ip = line.split()[1]
                    if IP_RE.fullmatch(ip):
                        ips.add(ip)
    except Exception:
        pass
    return ips


def is_internal(ip: str) -> bool:
    addr = ipaddress.IPv4Address(ip)
    return any(addr in ipaddress.IPv4Network(net) for net in INTERNAL_NETS)


def build_trusted_set():
    """Whitelist + resolv.conf; resolv IPs stored with mac=None."""
    trusted = set(read_whitelist())
    trusted.update((ip, None) for ip in resolv_conf_ips())
    return trusted


def _iptables(rule: str):
    subprocess.call(f"sudo sh -c '{rule}'", shell=True,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def block_attacker(ip: str, mac: str):
    for cmd in [
        f"iptables -C INPUT   -s {ip} -j DROP   || iptables -I INPUT   -s {ip} -j DROP",
        f"iptables -C OUTPUT  -d {ip} -j DROP   || iptables -I OUTPUT  -d {ip} -j DROP",
        f"iptables -C FORWARD -s {ip} -j DROP   || iptables -I FORWARD -s {ip} -j DROP",
        f"iptables -C INPUT   -m mac --mac-source {mac} -j DROP || iptables -I INPUT   -m mac --mac-source {mac} -j DROP",
        f"iptables -C FORWARD -m mac --mac-source {mac} -j DROP || iptables -I FORWARD -m mac --mac-source {mac} -j DROP",
    ]:
        _iptables(cmd)
    if (ip, mac) not in read_blocks():
        with BLOCKS.open("a") as f:
            f.write(f"{ip} {mac}\n")


def _trusted(src_ip: str, src_mac: str, trusted):
    internal = is_internal(src_ip)
    for ip, mac in trusted:
        if src_ip != ip:
            continue
        if internal:
            if mac is None or src_mac == mac:
                return True
        else:
            return True
    return False


def _blocked(src_ip: str, src_mac: str, blocks):
    return any(src_ip == ip and (m is None or src_mac == m) for ip, m in blocks)


def process_packet(pkt):
    if not (IP in pkt and UDP in pkt and pkt.haslayer(DNS)
            and pkt[DNS].qr == 1 and pkt[UDP].sport == 53):
        return

    src_ip  = pkt[IP].src
    src_mac = pkt[Ether].src.lower()

    trusted = build_trusted_set()
    blocks  = read_blocks()

    if _trusted(src_ip, src_mac, trusted):
        return

    already = _blocked(src_ip, src_mac, blocks)
    alert   = f"[ALERT] DNS spoofing | IP={src_ip} MAC={src_mac}" + (" (already blocked)" if already else "")
    print(alert)
    log_alert(alert)

    if already:
        return

    block_attacker(src_ip, src_mac)
    msg = f"[BLOCKED] {src_ip} {src_mac} (DNS spoofing) iptables DROP applied"
    print(msg)
    log_alert(msg)


# ───────── CLI / main ─────────
def _args():
    p = argparse.ArgumentParser(description="DNS anti-spoofing daemon")
    p.add_argument("--iface", help="interface to monitor (default: all)")
    p.add_argument("--loop", action="store_true", help="ignored (menu compat)")
    return p.parse_args()


def main():
    if os.geteuid() != 0:
        print("Run as root."); return
    args = _args()
    iface = args.iface or None
    print("[DNS Protection] strict mode active. Ctrl+C to stop.")
    sniff(filter=MONITOR_FILTER, prn=process_packet, store=0, iface=iface)


if __name__ == "__main__":
    main()
