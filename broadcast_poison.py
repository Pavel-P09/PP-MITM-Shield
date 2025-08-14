#!/usr/bin/env python3
"""
Broadcast spoof detector (IPv4)

Detects spoofed *responses* on:
  • LLMNR (UDP 5355)
  • mDNS  (UDP 5353)
  • NBNS  (UDP 137)
  • WS-Discovery (UDP 3702)

Rule: if any IPv4 advertised inside a response differs from the packet's IPv4
source, raise a single alert and block the host (iptables DROP by IP+MAC).
Subsequent traffic from the same MAC causes exactly one "already blocked"
notice per run. No hardcoded interfaces or IPs. Python 3.7–3.9 compatible.

Self‑protection: never alert/block the local machine (own MACs/IPs are ignored).
"""

import argparse
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional, Set, Tuple

from scapy.all import (  # type: ignore
    bind_layers,
    sniff,
    Ether,
    IP,
    UDP,
    Raw,
    DNS,
    DNSQR,
    DNSRR,
    get_if_list,
    get_if_hwaddr,
    get_if_addr,
)

# Force DNS dissection on mDNS/LLMNR ports (older Scapy may leave Raw)
bind_layers(UDP, DNS, sport=5355)
bind_layers(UDP, DNS, dport=5355)
bind_layers(UDP, DNS, sport=5353)
bind_layers(UDP, DNS, dport=5353)

BASE   = Path(__file__).resolve().parent
ALERTS = BASE / "alerts.log"
BLOCKS = BASE / "blocks.txt"
WHITE  = BASE / "whitelist.txt"

IP_RE  = re.compile(rb"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

notified_macs: Set[str] = set()
LOCAL_MACS: Set[str] = set()
LOCAL_IPS: Set[str] = set()

# ---------------- file & log helpers ----------------

def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_alert(msg: str) -> None:
    with ALERTS.open("a") as f:
        f.write(f"{now_str()} | {msg}\n")


def load_pairs(path: Path) -> Set[Tuple[str, Optional[str]]]:
    out: Set[Tuple[str, Optional[str]]] = set()
    if not path.exists():
        return out
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        ip = parts[0]
        mac = parts[1].lower() if len(parts) > 1 else None
        out.add((ip, mac))
    return out


def persist_block(ip: str, mac: str) -> None:
    cur = load_pairs(BLOCKS)
    if (ip, mac) not in cur:
        with BLOCKS.open("a") as f:
            f.write(f"{ip} {mac}\n")

# ---------------- iptables helpers -----------------

def sh(cmd: str) -> None:
    subprocess.call(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def drop_ip_mac(ip: str, mac: str) -> None:
    cmds = [
        f"iptables -C INPUT   -s {ip} -j DROP   || iptables -I INPUT   -s {ip} -j DROP",
        f"iptables -C OUTPUT  -d {ip} -j DROP   || iptables -I OUTPUT  -d {ip} -j DROP",
        f"iptables -C FORWARD -s {ip} -j DROP   || iptables -I FORWARD -s {ip} -j DROP",
        f"iptables -C INPUT   -m mac --mac-source {mac} -j DROP || iptables -I INPUT   -m mac --mac-source {mac} -j DROP",
        f"iptables -C FORWARD -m mac --mac-source {mac} -j DROP || iptables -I FORWARD -m mac --mac-source {mac} -j DROP",
    ]
    for c in cmds:
        sh(c)


def is_blocked(ip: str, mac: str) -> bool:
    bl = load_pairs(BLOCKS)
    for i, m in bl:
        if i == ip and (m is None or m == mac):
            return True
    return False


def is_whitelisted(ip: str, mac: str) -> bool:
    wl = load_pairs(WHITE)
    for i, m in wl:
        if i == ip and (m is None or m == mac):
            return True
    return False

# ---------------- local identity -------------------

def collect_local_identifiers(iface: Optional[str]) -> None:
    """Populate LOCAL_MACS and LOCAL_IPS for self-protection."""
    interfaces = [iface] if iface else list(get_if_list())
    for ifn in interfaces:
        try:
            mac = get_if_hwaddr(ifn).lower()
            if mac and mac != "00:00:00:00:00:00":
                LOCAL_MACS.add(mac)
        except Exception:
            pass
        try:
            ip = get_if_addr(ifn)
            if ip and ip != "0.0.0.0":
                LOCAL_IPS.add(ip)
        except Exception:
            pass

# ---------------- protocol helpers -----------------

def ensure_dns(pkt) -> None:
    if pkt.haslayer(DNS):
        return
    if pkt.haslayer(UDP) and (pkt[UDP].sport in (5353, 5355) or pkt[UDP].dport in (5353, 5355)):
        pl = pkt[UDP].payload
        if isinstance(pl, Raw):
            try:
                pkt[UDP].remove_payload()
                pkt[UDP].add_payload(DNS(pl.load))
            except Exception:
                pass


def extract_name(pkt) -> str:
    ensure_dns(pkt)
    try:
        if pkt.haslayer(DNS) and pkt[DNS].qdcount:
            return pkt[DNS].qd.qname.decode(errors="ignore")
    except Exception:
        pass
    return "broadcast"

# ---------------- detections -----------------------

def is_llmnr_mdns_spoof(pkt) -> bool:
    if pkt.haslayer("LLMNRResponse"):
        layer = pkt["LLMNRResponse"]
        src = pkt[IP].src
        try:
            answers = [rr.rdata for rr in getattr(layer, "an", []) if getattr(rr, "type", None) == 1]
            for a in answers:
                if a != src:
                    return True
        except Exception:
            return False
        return False
    ensure_dns(pkt)
    if pkt.haslayer(DNS) and pkt[DNS].qr == 1:
        src = pkt[IP].src
        answers = [rr.rdata for rr in pkt[DNS].an if rr.type == 1]
        for a in answers:
            if a != src:
                return True
    return False


def is_nbns_spoof(pkt) -> bool:
    # Must be UDP/137 in either direction
    if not (pkt.haslayer(UDP) and (pkt[UDP].sport == 137 or pkt[UDP].dport == 137)):
        return False

    # Get UDP payload bytes regardless of Scapy layer dissection
    try:
        payload = bytes(pkt[UDP].payload)
    except Exception:
        return False
    if len(payload) < 12:
        return False

    # NBNS header: ID(2) | FLAGS(2) | QD(2) | AN(2) | NS(2) | AR(2)
    flags = (payload[2] << 8) | payload[3]
    if (flags & 0x8000) == 0:
        return False  # only responses

    # Skip to first answer RR (we expect ANCOUNT >= 1)
    off = 12
    if off >= len(payload):
        return False

    # NAME: NetBIOS-encoded label: len=32 (0x20), then 32 bytes, then 0x00
    # (Most spoofers use uncompressed form; handle only this minimal case.)
    if payload[off] != 32 or off + 1 + 32 >= len(payload):
        return False
    off += 1 + 32
    if off >= len(payload) or payload[off] != 0x00:
        return False
    off += 1

    if off + 10 > len(payload):
        return False
    rr_type  = (payload[off] << 8) | payload[off+1]; off += 2
    rr_class = (payload[off] << 8) | payload[off+1]; off += 2
    off += 4  # TTL
    rdlen    = (payload[off] << 8) | payload[off+1]; off += 2
    if off + rdlen > len(payload):
        return False

    # TYPE 0x0020 (NB). RDATA: NBFLAGS(2) + IPv4(4)
    if rr_type != 0x0020 or rdlen < 6:
        return False
    adv_ip_bytes = payload[off+2:off+6]  # skip NBFLAGS(2)
    if len(adv_ip_bytes) != 4:
        return False

    adv_ip = ".".join(str(b) for b in adv_ip_bytes)
    src_ip = pkt[IP].src
    return adv_ip != src_ip


def is_wsd_spoof(pkt) -> bool:
    # Strict WS-Discovery: only UDP/3702 to multicast, and only XAddrs IPs in Probe/Resolve matches
    if not (pkt.haslayer(UDP) and pkt.haslayer(Raw) and pkt.haslayer(IP)):
        return False

    # dport must be 3702 and dst must be multicast (e.g. 239.255.255.250)
    if pkt[UDP].dport != 3702:
        return False
    try:
        dst_ip = pkt[IP].dst
        dst_oct = dst_ip.split(".")
        if len(dst_oct) != 4 or not (224 <= int(dst_oct[0]) <= 239):
            return False
    except Exception:
        return False

    raw = bytes(pkt[Raw].load)
    # Only consider ProbeMatches / ResolveMatches responses (not Hello/Bye/requests)
    if b"ProbeMatches" not in raw and b"ResolveMatches" not in raw:
        return False

    # Extract only host part from XAddrs URLs (ignore any other IPs in XML)
    # Examples: <d:XAddrs>http://192.168.0.123:80/device</d:XAddrs>
    xaddrs_ips = re.findall(rb"<[^>]*XAddrs[^>]*>([^<]+)</[^>]*XAddrs[^>]*>", raw)
    ips = []
    for blob in xaddrs_ips:
        # from "http://a.b.c.d:port/path ..." take the a.b.c.d
        m = re.search(rb"(?:https?://)?(\d{1,3}(?:\.\d{1,3}){3})", blob)
        if m:
            ips.append(m.group(1))

    if not ips:
        return False

    src = pkt[IP].src.encode()
    # Spoof only if ALL advertised addresses differ from src IP
    return all(ip != src for ip in ips)

# ---------------- packet handler -------------------

def handle(pkt) -> None:
    if not (pkt.haslayer(Ether) and pkt.haslayer(IP)):
        return
    mac = pkt[Ether].src.lower()
    ip = pkt[IP].src

    # Self-protection: never act on own traffic
    if mac in LOCAL_MACS or ip in LOCAL_IPS:
        return

    if is_whitelisted(ip, mac):
        return

    if not (is_llmnr_mdns_spoof(pkt) or is_nbns_spoof(pkt) or is_wsd_spoof(pkt)):
        return

    if is_blocked(ip, mac):
        if mac not in notified_macs:
            msg = f"{ip} ({mac}) already blocked"
            print(msg)
            log_alert(msg)
            notified_macs.add(mac)
        return

    msg = f"Poison from {ip} ({mac}) on '{extract_name(pkt)}' — blocked"
    print(msg)
    log_alert(msg)
    drop_ip_mac(ip, mac)
    persist_block(ip, mac)

# ---------------- main ----------------------------

def main() -> None:
    if os.geteuid() != 0:
        print("Run as root.")
        return
    ap = argparse.ArgumentParser(description="Broadcast spoof detector (LLMNR/mDNS/NBNS/WSD)")
    ap.add_argument("--iface", help="Interface to monitor (default: all)")
    ap.add_argument("--all-udp", action="store_true", help="Monitor all UDP ports instead of just poisoning ones")
    ap.add_argument("--loop", action="store_true", help="ignored (menu compat)")
    args, _ = ap.parse_known_args()

    collect_local_identifiers(args.iface)
    print("[Broadcast-Poison] active. Ctrl+C to stop.")
    if args.all_udp:
       bpf = "udp"
    else:
       bpf = "udp port 5355 or udp port 5353 or udp port 137 or udp port 3702"

    sniff(filter=bpf, prn=handle, store=0, iface=(args.iface or None))

if __name__ == "__main__":
    main()
