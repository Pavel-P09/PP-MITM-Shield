#!/usr/bin/env python3
"""
SSL-Strip detection module for PP-MultiShield.

Features
--------
* Detects two downgrade patterns:
  1. Outbound SYN to 443 followed by HTTP response from the same server on
     port 80 / 8081 / 8083 within TIMEOUT seconds.
  2. Any plaintext HTTP payload observed on TCP port 443.
* Blocks attacker by IP + MAC with duplicate-safe iptables rules.
* Persists blocks in blocks.txt and logs to alerts.log.
"""

import argparse
import os
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Tuple

from scapy.all import sniff, Ether, IP, TCP, Raw  # type: ignore

BASE = Path(__file__).resolve().parent
ALERT = BASE / "alerts.log"
WHITE = BASE / "whitelist.txt"
BLOCKS = BASE / "blocks.txt"

IP_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
MAC_RE = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")

TIMEOUT = 5  # seconds
HTTP_PORTS = {80, 8080, 8081, 8083}  # extend if needed

# ───────── helpers ─────────
def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_alert(msg: str) -> None:
    with ALERT.open("a") as f:
        f.write(f"{now()} | {msg}\n")


def _load_pairs(path: Path):
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


def _iptables(rule: str) -> None:
    subprocess.call(
        f"sudo sh -c '{rule}'", shell=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )


def block_attacker(ip: str, mac: str) -> None:
    for cmd in [
        f"iptables -C INPUT -s {ip} -j DROP   || iptables -I INPUT -s {ip} -j DROP",
        f"iptables -C OUTPUT -d {ip} -j DROP  || iptables -I OUTPUT -d {ip} -j DROP",
        f"iptables -C FORWARD -s {ip} -j DROP || iptables -I FORWARD -s {ip} -j DROP",
        f"iptables -C INPUT -m mac --mac-source {mac} -j DROP || "
        f"iptables -I INPUT -m mac --mac-source {mac} -j DROP",
        f"iptables -C FORWARD -m mac --mac-source {mac} -j DROP || "
        f"iptables -I FORWARD -m mac --mac-source {mac} -j DROP",
    ]:
        _iptables(cmd)

    if (ip, mac) not in _load_pairs(BLOCKS):
        with BLOCKS.open("a") as f:
            f.write(f"{ip} {mac}\n")


# cache: client_ip -> timestamp (last outbound SYN to 443)
https_cache: Dict[str, float] = {}

# ───────── packet handler ─────────
def process(pkt):
    if not (IP in pkt and TCP in pkt):
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    src_mac = pkt[Ether].src.lower()

    # --- outbound SYN to 443 ---
    if pkt[TCP].dport == 443 and pkt[TCP].flags & 0x02:
        https_cache[dst_ip] = time.time()  # key = client IP
        return

    # --- plaintext HTTP on port 443 ---
    if pkt[TCP].sport == 443 and Raw in pkt:
        first4 = bytes(pkt[Raw])[:4].upper()
        if first4.startswith(b"HTTP") or first4.startswith(b"GET ") or first4.startswith(b"POST"):
            handle_alert(src_ip, src_mac, note="HTTP on 443")
            return

    # --- HTTP response on typical downgrade ports ---
    if pkt[TCP].sport in HTTP_PORTS:
        t0 = https_cache.get(dst_ip)  # dst_ip is the client here
        if t0 and (time.time() - t0) <= TIMEOUT:
            handle_alert(src_ip, src_mac)
            https_cache.pop(dst_ip, None)


def handle_alert(attacker_ip: str, attacker_mac: str, note: str = "") -> None:
    wl = _load_pairs(WHITE)
    if any(attacker_ip == ip and (m is None or m == attacker_mac) for ip, m in wl):
        return

    blk = _load_pairs(BLOCKS)
    already = any(attacker_ip == ip and (m is None or m == attacker_mac) for ip, m in blk)
    tag = f" (already blocked)" if already else ""
    extra = f" [{note}]" if note else ""
    alert = f"[ALERT] SSL-Strip detected{extra} | IP={attacker_ip} MAC={attacker_mac}{tag}"
    print(alert)
    log_alert(alert)

    if already:
        return

    block_attacker(attacker_ip, attacker_mac)
    blocked_msg = f"[BLOCKED] {attacker_ip} {attacker_mac} (SSL-Strip)"
    print(blocked_msg)
    log_alert(blocked_msg)


# ───────── CLI / main ─────────
def _args():
    p = argparse.ArgumentParser(description="SSL-Strip detection daemon")
    p.add_argument("--iface", help="interface to monitor (default: all)")
    p.add_argument("--loop", action="store_true", help="ignored (menu compat)")
    return p.parse_args()


def main():
    if os.geteuid() != 0:
        print("Run as root.")
        return
    args = _args()
    iface = args.iface or None
    print("[SSL-Strip Detection] active. Ctrl+C to stop.")
    ports_filter = " or ".join(f"tcp port {p}" for p in sorted(HTTP_PORTS))
    bpf = f"{ports_filter} or tcp port 443"
    sniff(filter=bpf, prn=process, store=0, iface=iface)


if __name__ == "__main__":
    main()
