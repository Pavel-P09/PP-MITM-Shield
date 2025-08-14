#!/usr/bin/env python3
import argparse, os, re, subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional, Set, Tuple

from scapy.all import sniff, Ether, IP, TCP, Raw  # type: ignore

BASE   = Path(__file__).resolve().parent
ALERTS = BASE / "alerts.log"
WHITE  = BASE / "whitelist.txt"
BLOCKS = BASE / "blocks.txt"

IP_RE  = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
MAC_RE = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", re.I)

HTTP_PORTS = {80, 8080, 8081, 8083}

def now() -> str: return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
def log(msg: str) -> None:
    with ALERTS.open("a") as f: f.write(f"{now()} | {msg}\n")

def load_pairs(p: Path) -> Set[Tuple[str, Optional[str]]]:
    out = set()
    if not p.exists(): return out
    for raw in p.read_text().splitlines():
        raw = raw.split("#",1)[0].strip()
        if not raw: continue
        parts = raw.split()
        ip = parts[0]
        mac = parts[1].lower() if len(parts)>1 else None
        if IP_RE.fullmatch(ip) and (mac is None or MAC_RE.fullmatch(mac)):
            out.add((ip, mac))
    return out

def ipt(cmd: str) -> None:
    subprocess.call(f"sudo sh -c '{cmd}'", shell=True,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def block(ip: str, mac: str) -> None:
    for c in [
        f"iptables -C INPUT -s {ip} -j DROP   || iptables -I INPUT -s {ip} -j DROP",
        f"iptables -C OUTPUT -d {ip} -j DROP  || iptables -I OUTPUT -d {ip} -j DROP",
        f"iptables -C FORWARD -s {ip} -j DROP || iptables -I FORWARD -s {ip} -j DROP",
        f"iptables -C INPUT -m mac --mac-source {mac} -j DROP || iptables -I INPUT -m mac --mac-source {mac} -j DROP",
        f"iptables -C FORWARD -m mac --mac-source {mac} -j DROP || iptables -I FORWARD -m mac --mac-source {mac} -j DROP",
    ]: ipt(c)
    if (ip, mac) not in load_pairs(BLOCKS):
        with BLOCKS.open("a") as f: f.write(f"{ip} {mac}\n")

reported = set()
informed = set()

def is_http_redirect_to_plain(payload: bytes) -> bool:
    # Minimal check: HTTP status 30x and Location: http://
    head = payload[:512].replace(b"\r\n", b"\n")
    if not head.startswith(b"HTTP/1.") and not head.startswith(b"HTTP/2"):
        return False
    if b"\nLocation: http://" in head or b"\nlocation: http://" in head:
        if b" 30" in head[:16]:  # 301/302/307/308
            return True
    return False

def handle(pkt):
    if not (IP in pkt and TCP in pkt and Ether in pkt and Raw in pkt):
        return
    if pkt[TCP].sport not in HTTP_PORTS:
        return

    src_ip  = pkt[IP].src
    src_mac = pkt[Ether].src.lower()

    wl = load_pairs(WHITE)
    if any(src_ip == ip and (m is None or m == src_mac) for ip, m in wl):
        return

    blocks = load_pairs(BLOCKS)
    already = any(src_ip == ip and (m is None or m == src_mac) for ip, m in blocks)

    if not is_http_redirect_to_plain(bytes(pkt[Raw].load)):
        return

    key = (src_ip, src_mac)
    alert = f"[ALERT] HTTPS→HTTP redirect observed | IP={src_ip} MAC={src_mac}" + (" (already blocked)" if already else "")
    if key not in reported:
        print(alert); log(alert); reported.add(key)

    if already:
        if key not in informed:
            info = f"[INFO] {src_ip} ({src_mac}) already blocked"
            print(info); log(info); informed.add(key)
        return

    block(src_ip, src_mac)
    blk = f"[BLOCKED] {src_ip} {src_mac} (HTTP redirect)"
    print(blk); log(blk)

def main():
    if os.geteuid() != 0:
        print("Run as root."); return
    ap = argparse.ArgumentParser(description="HTTPS→HTTP redirect watcher")
    ap.add_argument("--iface", help="interface (default: all)")
    ap.add_argument("--loop", action="store_true", help="ignored (menu compat)")
    args, _ = ap.parse_known_args()
    ports = " or ".join(f"tcp port {p}" for p in sorted(HTTP_PORTS))
    bpf = ports
    print("[HTTP Redirect Watcher] active. Ctrl+C to stop.")
    sniff(filter=bpf, prn=handle, store=0, iface=(args.iface or None))

if __name__ == "__main__":
    main()
