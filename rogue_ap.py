#!/usr/bin/env python3
"""
Rogue-AP detector – clone hunter (stateless whitelist‑free)

How it works
------------
1. First encrypted beacon for each SSID becomes baseline (legitimate MAC).
2. If later an **open** beacon/probe advertises the *same SSID* with a *different MAC* ⇒ `[ALERT]` + `[BLOCKED]`.
3. MACs present in `blocks.txt` are treated as already blocked. If they re‑appear, script prints
   `[INFO] already blocked | <SSID> <MAC>` once per run.
4. One alert + one block per MAC per run.

Files
-----
alerts.log   – alerts / info
blocks.txt   – list of blocked MACs (persistent)
"""

import os, re, shutil, subprocess, sys, time
from datetime import datetime
from pathlib import Path
from typing import Dict, Tuple, Set, List

BASE = Path(__file__).resolve().parent
BLK_FILE = BASE / "blocks.txt"
LOG_FILE = BASE / "alerts.log"

MAC_RE   = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", re.I)
BSS_RE   = re.compile(r"^BSS\s+([0-9A-Fa-f:]{17})")       # iw
SSID_RE  = re.compile(r"^\s*SSID:\s*(.*)")
RSN_RE   = re.compile(r"^\s*(RSN:|WPA:)")
CELL_RE  = re.compile(r"Cell \d+ - Address: ([0-9A-Fa-f:]{17})")  # iwlist
ESSID_RE = re.compile(r'ESSID:"(.*)"')
NOENC_RE = re.compile(r"Encryption key:off")

SCAN_INT = 30  # seconds


def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log(msg: str) -> None:
    with LOG_FILE.open("a") as f:
        f.write(f"{now()} | {msg}\n")
    print(msg)


def run(cmd: List[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True).stdout

# Persistent blocked list
blocked: Set[str] = {m.lower() for m in MAC_RE.findall(BLK_FILE.read_text())} if BLK_FILE.exists() else set()

# For this run: baseline SSID→MAC  and reporting flags
baseline: Dict[str, str] = {}
alerted: Set[str] = set()
info_reported: Set[str] = set()  # already‑blocked messages sent


def block(mac: str) -> None:
    for c in (["ebtables","-A","INPUT","-s",mac,"-j","DROP"], ["iptables","-A","INPUT","-m","mac","--mac-source",mac,"-j","DROP"]):
        subprocess.run(["sudo", *c], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with BLK_FILE.open("a") as f:
        f.write(f"{mac} # {now()}\n")
    log(f"[BLOCKED] {mac}")


def scan(iface: str) -> Dict[str, Tuple[str, bool]]:
    out = run(["iw","dev",iface,"scan"]) if shutil.which("iw") else run(["iwlist",iface,"scanning"])
    res: Dict[str, Tuple[str, bool]] = {}
    mac = ssid = ""
    enc = False
    for line in out.splitlines():
        m = BSS_RE.match(line) or CELL_RE.search(line)
        if m:
            if mac:
                res[mac] = (ssid, enc)
            mac, ssid, enc = m.group(1).lower(), "", False
            continue
        if not mac:
            continue
        s = SSID_RE.match(line) or ESSID_RE.search(line)
        if s:
            ssid = s.group(1)
            continue
        if NOENC_RE.search(line):
            enc = False
        if RSN_RE.search(line):
            enc = True
    if mac:
        res[mac] = (ssid, enc)
    return res


def wifi_interfaces() -> List[str]:
    return [n for n in os.listdir("/sys/class/net") if n.startswith("wl")]


def main() -> None:
    if os.geteuid() != 0:
        sys.exit("Run as root")

    ifaces = wifi_interfaces()
    if not ifaces:
        sys.exit("No Wi‑Fi interface found")

    log(f"Started on {', '.join(ifaces)} | blocked {len(blocked)}")

    try:
        while True:
            for ifc in ifaces:
                for mac, (ssid, enc) in scan(ifc).items():
                    if not ssid:
                        continue
                    if ssid not in baseline and enc:
                        baseline[ssid] = mac  # first encrypted AP becomes baseline
                        continue

                    base_mac = baseline.get(ssid)
                    if not base_mac:
                        continue  # no baseline yet (open network first) – ignore

                    if mac == base_mac:
                        continue  # same AP as baseline

                    if mac in blocked:
                        if mac not in info_reported:
                            log(f"[INFO] already blocked | {ssid} {mac}")
                            info_reported.add(mac)
                        continue

                    if enc:
                        continue  # encrypted clone – ignore

                    if mac in alerted:
                        continue

                    log(f"[ALERT] open clone | {ssid} {mac}")
                    block(mac)
                    blocked.add(mac)
                    alerted.add(mac)
            time.sleep(SCAN_INT)
    except KeyboardInterrupt:
        print("Stopped.")


if __name__ == "__main__":
    main()
