import os
import subprocess
import sys
import time
import threading
import tty
import termios
from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon

networks = {}
clients = set()
running = True

# ------------------ COLORS ------------------
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"

# ------------------ YOUR OWL BANNER ------------------
def banner():
    print(f"""{CYAN}
   huuhuu

    ,_,  
   (o,o) 
   (   )
    " "

 WiFi Scanner
{RESET}""")

# ------------------ MENU ------------------
def menu():
    print("1) Scan all")
    print("2) Open only")
    print("3) Weak only")
    print("4) Focus BSSID")
    print("5) Exit")

    c = input("Choice: ").strip()

    if c == "1": return {}
    if c == "2": return {"open": True}
    if c == "3": return {"weak": True}
    if c == "4":
        return {"target": input("BSSID: ").strip()}
    if c == "5": sys.exit(0)

    return {}

# ------------------ HELPERS ------------------
def band(ch):
    try: return "2.4G" if int(ch) <= 14 else "5G"
    except: return "?"

def security(c):
    s = " ".join(c)
    if "WPA3" in s or "WPA2" in s: return "Secure"
    if "WPA" in s: return "Weak"
    if "WEP" in s: return "Broken"
    return "Open"

def sig_label(s):
    if s > -50: return "Strong"
    if s > -70: return "Medium"
    return "Weak"

# ------------------ DISPLAY ------------------
def display(f):
    os.system("clear")
    banner()

    total = len(networks)
    open_n = sum(1 for n in networks.values() if security(n["crypto"]) == "Open")
    strongest = max(networks.values(), key=lambda x: x["sig"])["ssid"] if networks else "-"

    print(f"{CYAN}CTRL+A → menu | CTRL+C → exit{RESET}")
    print(f"{GREEN}Networks:{total}  Open:{open_n}  Clients:{len(clients)}  Strongest:{strongest}{RESET}\n")

    print(f"{'SSID':15} {'BSSID':17} {'CH':3} {'B':4} {'RSSI':5} {'SIG':6} {'SEC':7} {'CL'}")
    print("-"*85)

    for bssid, d in sorted(networks.items(), key=lambda x: x[1]["sig"], reverse=True):

        sec = security(d["crypto"])

        if f.get("open") and sec != "Open": continue
        if f.get("weak") and sec not in ["Weak","Broken","Open"]: continue
        if f.get("target") and f["target"] != bssid: continue

        if sec == "Open":
            color = RED
        elif sec in ["Weak","Broken"]:
            color = YELLOW
        else:
            color = GREEN

        print(f"{color}{d['ssid'][:15]:15} {bssid:17} {d['ch']:3} {band(d['ch']):4} {d['sig']:5} {sig_label(d['sig']):6} {sec:7} {len(d.get('clients',[]))}{RESET}")

# ------------------ KEY LISTENER ------------------
def key_listener():
    global running
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        while True:
            if sys.stdin.read(1) == '\x01':  # CTRL+A
                running = False
                break
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)

# ------------------ PACKETS ------------------
def handler(p, f):
    global running
    if not running: return

    if p.haslayer(Dot11):
        if p.addr1: clients.add(p.addr1)
        if p.addr2: clients.add(p.addr2)

    if p.haslayer(Dot11Beacon):
        bssid = p[Dot11].addr2
        ssid = p.info.decode(errors="ignore") or "<hidden>"

        stats = p[Dot11Beacon].network_stats()
        ch = stats.get("channel")
        crypto = stats.get("crypto", [])

        try: sig = p.dBm_AntSignal
        except: sig = -100

        if bssid not in networks:
            networks[bssid] = {"count":0, "clients":[]}

        networks[bssid].update({
            "ssid": ssid,
            "ch": ch,
            "crypto": crypto,
            "sig": sig
        })

        networks[bssid]["count"] += 1

        display(f)

# ------------------ CHANNEL HOPPING ------------------
def hop(i):
    global running
    while running:
        for c in range(1,14):
            subprocess.run(["iwconfig", i, "channel", str(c)],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
            time.sleep(0.4)

# ------------------ GET MONITOR ------------------
def get_mon():
    out = subprocess.run(["iwconfig"], capture_output=True, text=True).stdout
    for l in out.splitlines():
        if "Mode:Monitor" in l:
            return l.split()[0]
    return None

# ------------------ CLEANUP ------------------
def cleanup(i):
    if i:
        subprocess.run(["airmon-ng","stop",i], stdout=subprocess.DEVNULL)
    subprocess.run(["systemctl","restart","NetworkManager"], stdout=subprocess.DEVNULL)

# ------------------ MAIN ------------------
while True:
    os.system("clear")
    banner()

    iface = input("Interface: ").strip()
    if not iface: continue

    subprocess.run(["airmon-ng","check","kill"], stdout=subprocess.DEVNULL)
    subprocess.run(["airmon-ng","start",iface], stdout=subprocess.DEVNULL)

    mon = get_mon()
    if not mon:
        print("Monitor mode failed")
        time.sleep(2)
        continue

    filters = menu()

    running = True
    networks.clear()
    clients.clear()

    threading.Thread(target=key_listener, daemon=True).start()
    threading.Thread(target=hop, args=(mon,), daemon=True).start()

    try:
        sniff(iface=mon, prn=lambda p: handler(p,filters), store=0, monitor=True)
    except KeyboardInterrupt:
        cleanup(mon)
        sys.exit(0)

    cleanup(mon)
