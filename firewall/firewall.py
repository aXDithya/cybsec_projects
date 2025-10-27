#!/usr/bin/env python3
"""
Personal Firewall - lightweight sniffer + iptables enforcer
Run with sudo/root.
"""
import json
import subprocess
import logging
import threading
from datetime import datetime
from dateutil import tz
from scapy.all import sniff, IP, TCP, UDP, Raw

RULES_FILE = "rules.json"
LOG_FILE = "firewall.log"

# Setup logger
logging.basicConfig(filename=LOG_FILE,
                    level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s')

def load_rules():
    with open(RULES_FILE) as f:
        return json.load(f)

def iptables_block_ip(ip, direction='INPUT'):
    # idempotent: check if rule exists before adding
    check_cmd = ["iptables", "-C", direction, "-s", ip, "-j", "DROP"]
    add_cmd = ["iptables", "-I", direction, "1", "-s", ip, "-j", "DROP"]
    try:
        subprocess.run(check_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # rule exists
        logging.debug(f"iptables rule already exists for {ip}")
    except subprocess.CalledProcessError:
        # add rule
        subprocess.run(add_cmd, check=True)
        logging.info(f"Added iptables DROP for {ip} on {direction}")

def iptables_block_ip_port(ip, port, proto='tcp', direction='INPUT'):
    # port-based blocking
    check_cmd = ["iptables", "-C", direction, "-s", ip, "-p", proto, "--sport" if direction=="INPUT" else "--dport", str(port), "-j", "DROP"]
    add_cmd = ["iptables", "-I", direction, "1", "-s", ip, "-p", proto, "--sport" if direction=="INPUT" else "--dport", str(port), "-j", "DROP"]
    try:
        subprocess.run(check_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        subprocess.run(add_cmd, check=True)
        logging.info(f"Added iptables DROP for {ip}:{port}/{proto} on {direction}")

def handle_packet(pkt, rules):
    try:
        if IP not in pkt:
            return
        ip_layer = pkt[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = ip_layer.proto

        # Basic packet data
        info = {"ts": datetime.now().isoformat(), "src": src, "dst": dst, "proto": proto}
        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            info.update({"sport": sport, "dport": dport, "l4": "TCP"})
        elif UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            info.update({"sport": sport, "dport": dport, "l4": "UDP"})

        # Logging every packet (can be noisy - adjust level)
        logging.debug(f"PKT: {info}")

        # Check rules
        # rules structure example (see rules.json below)
        # "block_ips": ["1.2.3.4"],
        # "block_ports": [{"ip": "1.2.3.4", "port": 22, "proto": "tcp"}],
        # "allow_ips": [...]
        # match block-by-ip
        if src in rules.get("block_ips", []) or dst in rules.get("block_ips", []):
            logging.warning("Blocked by IP rule: " + json.dumps(info))
            iptables_block_ip(src)
            return

        # match port block
        bports = rules.get("block_ports", [])
        for bp in bports:
            if ('ip' in bp and bp['ip'] in (src, dst)) and ('port' in bp):
                # direction: if src==bp.ip treat as INPUT block of that IP's source port
                iptables_block_ip_port(bp['ip'], bp['port'], bp.get('proto','tcp'))
                logging.warning("Blocked by port rule: " + json.dumps({**info, **bp}))
                return

        # whitelist check (if whitelist mode enabled)
        if rules.get("whitelist_mode"):
            allowed = rules.get("allow_ips", [])
            if not (src in allowed or dst in allowed):
                logging.warning("Not whitelisted: " + json.dumps(info))
                iptables_block_ip(src)
                return

    except Exception as e:
        logging.exception("Error handling packet: " + str(e))

def start_sniff(rules):
    # sniff both incoming & outgoing
    sniff(prn=lambda p: handle_packet(p, rules), store=0)

def reload_rules_periodically(interval=30):
    global RULES
    while True:
        try:
            RULES.update(load_rules())
            logging.debug("Rules reloaded")
        except Exception as e:
            logging.exception("Failed to reload rules: " + str(e))
        import time; time.sleep(interval)

if __name__ == "__main__":
    # quick safety: must be run as root
    import os, sys
    if os.geteuid() != 0:
        print("Please run as root (sudo). Exiting.")
        sys.exit(1)

    RULES = load_rules()
    # start rule reload thread
    t = threading.Thread(target=reload_rules_periodically, args=(15,), daemon=True)
    t.start()
    print("Starting packet sniffing... (press Ctrl+C to stop)")
    try:
        start_sniff(RULES)
    except KeyboardInterrupt:
        print("Stopping...")

