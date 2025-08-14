#!/usr/bin/env python3
"""
Learning / Lists / Firewall / Logs logic
(restored behaviour of the original main.py)
"""

import os
import re
import subprocess
import time
import ipaddress
from datetime import datetime, timedelta
from typing import List, Optional, Tuple

def get_arp_table():
    hosts = []
    try:
        out = subprocess.check_output("ip neigh", shell=True, text=True)
        for line in out.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+([0-9a-f:]{17})\s+\w+", line, re.I)
            if m:
                hosts.append((m.group(1), m.group(2).lower()))
    except subprocess.CalledProcessError:
        pass
    return hosts

BASE_DIR  = os.path.dirname(os.path.realpath(__file__))

WHITELIST = os.path.join(BASE_DIR, "whitelist.txt")
BLACKLIST = os.path.join(BASE_DIR, "blacklist.txt")
BLOCKS    = os.path.join(BASE_DIR, "blocks.txt")
ALERTS    = os.path.join(BASE_DIR, "alerts.log")

# ───────── ui helpers ─────────
def safe_input(prompt: str) -> Optional[str]:
    try:
        return input(prompt)
    except KeyboardInterrupt:
        print()
        return None

def print_menu(title: str, items: List[str]) -> None:
    width = 72
    print("=" * width)
    print(title.center(width))
    print("=" * width)
    for idx, item in enumerate(items, 1):
        print(f"[{idx}] {item}")
    print("=" * width)

def pause(msg: str = "Press Enter to continue...") -> None:
    if safe_input(msg) is None:
        return

# ───────── alert helpers ─────────
def trim_alerts_log(days: int = 2) -> None:
    cutoff = datetime.now() - timedelta(days=days)
    if not os.path.exists(ALERTS):
        return
    keep: List[str] = []
    with open(ALERTS) as f:
        for line in f:
            ts = line.split("|", 1)[0].strip()
            try:
                if datetime.strptime(ts, "%Y-%m-%d %H:%M:%S") >= cutoff:
                    keep.append(line)
            except ValueError:
                continue
    with open(ALERTS, "w") as f:
        f.writelines(keep)

def log_alert(msg: str) -> None:
    trim_alerts_log()
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(ALERTS, "a") as f:
        f.write(f"{ts} | {msg}\n")

# ───────── iptables ─────────
def flush_iptables_block(ip: str, mac: Optional[str] = None) -> None:
    for chain in ("INPUT", "OUTPUT", "FORWARD"):
        subprocess.call(f"sudo iptables -D {chain} -s {ip} -j DROP", shell=True)
    if mac and mac.count(":") == 5:
        for chain in ("INPUT", "FORWARD"):
            subprocess.call(
                f"sudo iptables -D {chain} -m mac --mac-source {mac} -j DROP",
                shell=True)

# ───────── file list helpers ─────────
def show_file(path: str, title: str) -> None:
    print(f"\n{title}\n" + "-" * 72)
    if not os.path.exists(path) or not open(path).read().strip():
        print("(Empty)")
    else:
        with open(path) as f:
            for i, line in enumerate(f, 1):
                print(f"{i}. {line.strip()}")
    print("-" * 72)
    pause()

def add_entries(fname: str) -> None:
    raw = safe_input("Enter entries (IP MAC, comma separated): ")
    if raw is None or not raw.strip():
        return
    with open(fname, "a") as f:
        for token in raw.strip().split(","):
            token = token.strip()
            if not token:
                continue
            parts = token.split()
            ip = parts[0]
            mac = parts[1].lower() if len(parts) > 1 else ""
            if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip) and (
                not mac or re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac)):
                f.write(f"{ip} {mac}\n" if mac else f"{ip}\n")
            else:
                print(f"Invalid entry: {token}")

def remove_entry(fname: str, is_block: bool = False) -> None:
    if not os.path.exists(fname) or not open(fname).read().strip():
        print("List is empty."); pause(); return
    with open(fname) as f:
        lines = f.readlines()
    for i, line in enumerate(lines, 1):
        print(f"[{i}] {line.strip()}")
    sel = safe_input("Number to remove (0 cancel): ")
    if sel in (None, "0"):
        return
    try:
        idx = int(sel)
        if 1 <= idx <= len(lines):
            ip, *rest = lines[idx - 1].strip().split()
            mac = rest[0] if rest else None
            with open(fname, "w") as f:
                f.writelines(l for j, l in enumerate(lines, 1) if j != idx)
            if is_block:
                flush_iptables_block(ip, mac)
            print("Entry removed.")
        else:
            print("Invalid number.")
    except ValueError:
        print("Invalid input.")
    pause()

def simple_list_menu(fname: str, title: str) -> None:
    while True:
        print_menu(title, ["Show list", "Add entries", "Remove entry", "Back"])
        sel = safe_input("Select option: ")
        if sel is None or sel == "4":
            return
        sel = sel.strip()
        if sel == "1":
            show_file(fname, f"{title} Entries")
        elif sel == "2":
            add_entries(fname); pause("Entries added.")
        elif sel == "3":
            remove_entry(fname)
        else:
            print("Invalid input.")

# ───────── blocks / firewall ─────────
def clear_blocks() -> None:
    if not os.path.exists(BLOCKS) or not open(BLOCKS).read().strip():
        print("Blocks list is already empty."); pause(); return
    if safe_input("Clear ALL blocks? (y/n): ") != "y":
        return
    with open(BLOCKS) as f:
        for line in f:
            ip, *rest = line.strip().split()
            mac = rest[0] if rest else None
            flush_iptables_block(ip, mac)
    open(BLOCKS, "w").close()
    log_alert("All blocks cleared by user."); pause("All blocks cleared.")

def blocks_menu() -> None:
    while True:
        print_menu("Blocks Management",
                   ["Show list", "Remove entry", "Clear all blocks", "Back"])
        sel = safe_input("Select option: ")
        if sel is None or sel == "4":
            return
        sel = sel.strip()
        if sel == "1":
            show_file(BLOCKS, "Blocks List")
        elif sel == "2":
            remove_entry(BLOCKS, is_block=True)
        elif sel == "3":
            clear_blocks()
        else:
            print("Invalid input.")

def firewall_menu() -> None:
    while True:
        print_menu("Firewall rules",
                   ["Show current rules", "Delete all rules", "Back"])
        sel = safe_input("Select option: ")
        if sel is None or sel == "3":
            return
        sel = sel.strip()
        if sel == "1":
            os.system("sudo iptables -L -n -v"); pause()
        elif sel == "2":
            if safe_input("Delete ALL rules? (y/n): ") == "y":
                os.system("sudo iptables -F"); os.system("sudo iptables -X")
                open(BLOCKS, "w").close()
                log_alert("All firewall rules and blocks deleted by user.")
                pause("Rules cleared.")
        else:
            print("Invalid input.")

def smart_learning() -> None:
    from scapy.all import srp, Ether, ARP, conf      # type: ignore
    print("\n[Smart Learning] Scanning network...")
    first = subprocess.check_output(
        "ip -4 -o addr show scope global", shell=True, text=True).splitlines()[0]
    ip_s, pre = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", first).groups()
    net = ipaddress.IPv4Network(f"{ip_s}/{pre}", strict=False)
    conf.verb = 0
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net)), timeout=2)

    hosts = sorted({(r.psrc, r.hwsrc.lower()) for _, r in ans}) or get_arp_table()
    if not hosts:
        print("No active hosts detected."); pause(); return

    print(f"Found {len(hosts)} host(s):")
    for i, (ip_a, mac_a) in enumerate(hosts, 1):
        print(f" {i:>2}) {ip_a:<15} {mac_a}")

    prompt = safe_input(
        "\nSelect hosts to whitelist "
        "(numbers separated by space, 'a' = all, empty = cancel): ")
    if prompt is None or not prompt.strip():
        pause(); return

    tokens = prompt.replace(",", " ").split()
    if tokens[0].lower() in ("a", "all"):
        selected = hosts
    else:
        try:
            idxs = {int(t) for t in tokens}
        except ValueError:
            print("Invalid input."); pause(); return
        selected = [hosts[i - 1] for i in sorted(idxs) if 1 <= i <= len(hosts)]
        if not selected:
            print("No valid numbers."); pause(); return

    with open(WHITELIST, "a") as f:
        for ip_a, mac_a in selected:
            f.write(f"{ip_a} {mac_a}\n")
    print("Written.")
    pause()

# ───────── top menu ─────────
def learning_menu() -> None:
    while True:
        print_menu("Learning / Lists / Firewall / Logs",
                   ["Smart Learning", "Whitelist", "Blacklist", "Blocks",
                    "Firewall rules", "Logs / Alerts", "Back to Main Menu"])
        sel = safe_input("Select option: ")
        if sel is None or sel == "7":
            return
        sel = sel.strip()
        if sel == "1":
            smart_learning()
        elif sel == "2":
            simple_list_menu(WHITELIST, "Whitelist Management")
        elif sel == "3":
            simple_list_menu(BLACKLIST, "Blacklist Management")
        elif sel == "4":
            blocks_menu()
        elif sel == "5":
            firewall_menu()
        elif sel == "6":
            show_file(ALERTS, "Alerts Log")
        else:
            print("Invalid input.")
