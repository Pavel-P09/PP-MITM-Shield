#!/usr/bin/env python3
"""
PP-MultiShield – core launcher
(the whole learning / lists / firewall block is delegated to learning_menu.py)
"""

import os
import sys
import subprocess
import time

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
REQUIRED_FILES = [
    LOG_DIR / "alerts.log",
    BASE_DIR / "whitelist.txt",
    BASE_DIR / "blocks.txt",
    BASE_DIR / "blacklist.txt",
]

def ensure_project_files() -> None:
    LOG_DIR.mkdir(exist_ok=True)
    for p in REQUIRED_FILES:
        p.touch(exist_ok=True)

ensure_project_files()


# ───────── ui helpers ─────────
def print_menu(title: str, items: list[str]) -> None:
    width = 72
    print("=" * width)
    print(title.center(width))
    print("=" * width)
    for idx, item in enumerate(items, 1):
        print(f"[{idx}] {item}")
    print("=" * width)

def safe_input(prompt: str):
    try:
        return input(prompt)
    except KeyboardInterrupt:
        print()  # newline after ^C
        return None

# ───────── protection launcher ─────────
def run_module(cmd: list[str], desc: str) -> None:
    try:
        proc = subprocess.Popen(cmd)
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        print(f"\n[{desc}] stopped.")
        time.sleep(1)

def protection_menu() -> None:
    items = [
        "Start ARP Protection",
        "Start DNS Protection",
        "Start DHCP Protection",
        "Start SSL-Strip Detection",
        "Start Rogue-AP Detection",
        "Start Broadcast-Poison Protection",
        "Start ICMP Redirect Protection",
        "Start HTTPS→HTTP Redirect Watcher",
        "Start All Protections",
        "Back"
    ]
    scripts = {
        "1": "arp_protect.py",
        "2": "dns_protect.py",
        "3": "dhcp_protect.py",
        "4": "ssl_strip_detect.py",
        "5": "rogue_ap.py",
        "6": "broadcast_poison.py",
        "7": "icmp_redirect_guard.py",
        "8": "http_redirect_watch.py"
    }

    while True:
        print_menu("Protection & Monitoring Modules", items)
        sel = safe_input("Select option: ")
        if sel is None:
            return
        sel = sel.strip()

        if sel in scripts:  # launch single module
            iface = safe_input("Interface (empty = all): ")
            if iface is None:
                continue
            iface = iface.strip()

            cmd = ["sudo", "python3",
                   os.path.join(BASE_DIR, scripts[sel]), "--loop"]

            # Optional ALL-UDP only for broadcast_poison.py
            if scripts[sel] == "broadcast_poison.py":
                all_udp = safe_input("Monitor ALL UDP ports? (y/n): ")
                if all_udp and all_udp.lower() == "y":
                    cmd.append("--all-udp")

            if iface:
                cmd.extend(["--iface", iface])

            run_module(cmd, items[int(sel) - 1][6:])

        elif sel == "9":  # start all protections
            iface = safe_input("Interface for all (empty = all): ")
            if iface is None:
                continue
            iface = iface.strip()

            all_udp_choice = safe_input("Monitor ALL UDP ports in Broadcast-Poison? (y/n): ")
            all_udp = bool(all_udp_choice and all_udp_choice.lower() == "y")

            procs = []
            try:
                # start in menu order
                for key in sorted(scripts.keys(), key=int):
                    script = scripts[key]
                    cmd = ["sudo", "python3",
                           os.path.join(BASE_DIR, script), "--loop"]
                    if script == "broadcast_poison.py" and all_udp:
                        cmd.append("--all-udp")
                    if iface:
                        cmd.extend(["--iface", iface])
                    procs.append(subprocess.Popen(cmd))
                while True:
                    time.sleep(2)
            except KeyboardInterrupt:
                for p in procs:
                    p.terminate()
                print("\nAll protections stopped.")
                time.sleep(1)

        elif sel == "10":  # back
            return
        else:
            print("Invalid input.")

# ───────── main menu ─────────
def main_menu() -> None:
    import learning_menu as lm  # lazy import
    while True:
        print_menu("PP-MultiShield – Main Menu",
                   ["Learning / Lists / Firewall / Logs",
                    "Protection & Monitoring Modules",
                    "Exit"])
        choice = safe_input("Select section: ")
        if choice is None:
            print("Goodbye.")
            sys.exit(0)
        choice = choice.strip()

        if choice == "1":
            lm.learning_menu()
        elif choice == "2":
            protection_menu()
        elif choice == "3":
            print("Goodbye.")
            sys.exit(0)
        else:
            print("Invalid input.")

if __name__ == "__main__":
    main_menu()
