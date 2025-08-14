#!/usr/bin/env python3
import argparse, ipaddress, os, re, subprocess, time
from pathlib import Path
from typing import Dict, Set, Tuple, Optional

BASE = Path(__file__).resolve().parent
ALERT = BASE / "alerts.log"
BLOCK = BASE / "blocks.txt"
WHITE = BASE / "whitelist.txt"

IP_MAC = re.compile(r"([\d.]+)\s+dev\s+\S+\s+lladdr\s+([0-9a-f:]{17})\s+(\w+)", re.I)

observed: Dict[str, str] = {}
alerted:  Set[Tuple[str, str]] = set()

# discover local subnets once
NETS = []
for line in subprocess.check_output(
        "ip -o -4 addr show scope global", shell=True, text=True).splitlines():
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", line)
    if m:
        ip, mask = m.groups()
        NETS.append(ipaddress.ip_network(f"{ip}/{mask}", strict=False))

def internal(ip: str) -> bool:
    ip_o = ipaddress.ip_address(ip)
    return any(ip_o in n for n in NETS)

def run(rule: str) -> None:
    subprocess.call(["sudo", "sh", "-c", rule],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def persist(ip: str, mac: str) -> None:
    line = f"{ip} {mac}\n"
    if BLOCK.exists() and line in BLOCK.read_text():
        return
    with BLOCK.open("a") as f:
        f.write(line)

def block(ip: str, mac: str) -> None:
    rules = [
        f"iptables -C INPUT   -m mac --mac-source {mac} -j DROP || "
        f"iptables -I INPUT   -m mac --mac-source {mac} -j DROP",
        f"iptables -C FORWARD -m mac --mac-source {mac} -j DROP || "
        f"iptables -I FORWARD -m mac --mac-source {mac} -j DROP",
    ]
    if not internal(ip):
        rules += [
            f"iptables -C INPUT   -s {ip} -j DROP || "
            f"iptables -I INPUT   -s {ip} -j DROP",
            f"iptables -C OUTPUT  -d {ip} -j DROP || "
            f"iptables -I OUTPUT  -d {ip} -j DROP",
            f"iptables -C FORWARD -s {ip} -j DROP || "
            f"iptables -I FORWARD -s {ip} -j DROP",
        ]
    for r in rules:
        run(r)
    persist(ip, mac)

def arp_table(iface: Optional[str] = None) -> Dict[str, str]:
    tbl: Dict[str, str] = {}
    cmd = "ip neigh"
    if iface:
        cmd += f" show dev {iface}"
    out = subprocess.check_output(cmd, shell=True, text=True)
    for line in out.splitlines():
        m = IP_MAC.match(line)
        if m and m.group(3) in ("REACHABLE", "STALE", "DELAY", "PROBE"):
            tbl[m.group(1)] = m.group(2).lower()
    return tbl

def whitelist() -> Dict[str, Optional[str]]:
    data: Dict[str, Optional[str]] = {}
    if WHITE.exists():
        for raw in WHITE.read_text().splitlines():
            raw = raw.split("#", 1)[0].strip()
            if raw:
                ip, *rest = raw.split()
                data[ip] = rest[0].lower() if rest else None
    return data

def blocked_ips() -> Set[str]:
    if not BLOCK.exists():
        return set()
    return {l.split()[0] for l in BLOCK.read_text().splitlines() if l.strip()}

def log(msg: str) -> None:
    with ALERT.open("a") as f:
        f.write(msg + "\n")

def protect(iface: Optional[str] = None) -> None:
    wl  = whitelist()
    blk = blocked_ips()
    print("[ARP Protection] Running. Ctrl+C to stop.")
    while True:
        for ip, mac in arp_table(iface).items():
            pair = (ip, mac)

            if ip in wl and (wl[ip] in (None, mac)):
                observed[ip] = mac
                continue

            if ip not in observed:
                observed[ip] = mac
                continue

            if ip in blk:
                if pair not in alerted:
                    msg = f"[ALERT] ARP spoofing | IP={ip} MAC={mac} (already blocked)"
                    print(msg)
                    log(msg)
                    alerted.add(pair)
                continue

            if observed[ip] != mac:
                msg = f"[ALERT] ARP spoofing | IP={ip} MAC={mac}"
                print(msg)
                log(msg)
                block(ip, mac)
                blk.add(ip)
                block_msg = f"[BLOCKED] {ip} {mac}"
                print(block_msg)
                log(block_msg)
                alerted.add(pair)
                observed[ip] = mac
        time.sleep(5)

def main() -> None:
    if os.geteuid() != 0:
        print("Run as root.")
        return
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--loop", action="store_true")
    parser.add_argument("--iface")
    args = parser.parse_known_args()[0]
    try:
        protect(args.iface)
    except KeyboardInterrupt:
        print("\n[ARP Protection] stopped.")

if __name__ == "__main__":
    main()
