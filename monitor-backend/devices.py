import os
import time
import subprocess
from datetime import datetime
from collections import defaultdict
import platform
import scapy.all as scapy
import threading
import queue


class NetworkDeviceMonitor:
    def __init__(self):
        self.devices = {}  
        self.new_devices = queue.Queue()
        self.lost_devices = queue.Queue()
        self.scan_interval = 60 
        self.inactive_threshold = 300 
        self.network_prefix = self.get_network_prefix()
        self.running = False
        self.arp_table = defaultdict(int)

    def get_network_prefix(self):
        """Determine the network IP prefix (first 3 octets)"""
        try:
            if platform.system() == "Linux":
                result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
                lines = result.stdout.splitlines()
                for line in lines:
                    if 'src' in line:
                        parts = line.split()
                        ip_index = parts.index('src') + 1
                        ip = parts[ip_index]
                        return '.'.join(ip.split('.')[:3]) + '.0/24'
            elif platform.system() == "Windows":
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                lines = result.stdout.splitlines()
                for line in lines:
                    if 'IPv4 Address' in line:
                        ip = line.split(':')[-1].strip()
                        return '.'.join(ip.split('.')[:3]) + '.0/24'
        except Exception:
            pass
        return '192.168.1.0/24'  # Default if detection fails

    def arp_scan(self):
        """Perform ARP scan of the network"""
        try:
            answered, _ = scapy.arping(self.network_prefix, timeout=2, verbose=False)
            current_time = datetime.now()
            current_macs = set()

            for sent, received in answered:
                mac = received.hwsrc
                ip = received.psrc
                current_macs.add(mac)

                # New device detection
                if mac not in self.devices:
                    self.devices[mac] = {
                        'ip': ip,
                        'last_seen': current_time,
                        'name': self.get_device_name(ip),
                        'status': 'Active',
                        'first_seen': current_time
                    }
                    self.new_devices.put((mac, self.devices[mac]))
                    print(f"[+] New device: {mac} ({self.devices[mac]['name']}) at {ip}")
                else:
                    # Update existing device
                    self.devices[mac]['last_seen'] = current_time
                    if self.devices[mac]['status'] != 'Active':
                        self.devices[mac]['status'] = 'Active'
                        print(f"[~] Device reconnected: {mac} ({self.devices[mac]['name']}) at {ip}")

            # Check for lost devices
            lost_macs = set(self.devices.keys()) - current_macs
            for mac in lost_macs:
                if (current_time - self.devices[mac]['last_seen']).total_seconds() > self.inactive_threshold:
                    if self.devices[mac]['status'] != 'Inactive':
                        self.devices[mac]['status'] = 'Inactive'
                        self.lost_devices.put((mac, self.devices[mac]))
                        print(f"[-] Device inactive: {mac} ({self.devices[mac]['name']})")

        except Exception as e:
            print(f"Scan error: {str(e)}")

    def get_device_name(self, ip):
        """Try to resolve device name"""
        try:
            if platform.system() == "Linux":
                result = subprocess.run(['avahi-resolve', '-a', ip], capture_output=True, text=True)
                if result.returncode == 0:
                    return result.stdout.split()[-1]
            # Fallback to generic name
            return f"Device-{ip.split('.')[-1]}"
        except:
            return f"Device-{ip.split('.')[-1]}"

    def monitor_arp(self):
        """Continuously monitor ARP traffic"""
        def packet_callback(packet):
            if packet.haslayer(scapy.ARP):
                self.arp_table[packet[scapy.ARP].hwsrc] += 1

        scapy.sniff(prn=packet_callback, filter="arp", store=0)

    def update_status(self):
        """Periodically update device status"""
        while self.running:
            current_time = datetime.now()
            for mac, info in self.devices.items():
                inactive_time = (current_time - info['last_seen']).total_seconds()
                if inactive_time > self.inactive_threshold and info['status'] == 'Active':
                    self.devices[mac]['status'] = 'Inactive'
                    self.lost_devices.put((mac, self.devices[mac]))
                    print(f"[-] Device marked inactive: {mac} ({info['name']})")
            time.sleep(10)

    def start(self):
        """Start the monitoring process"""
        self.running = True
        
        # Start ARP monitoring thread
        arp_thread = threading.Thread(target=self.monitor_arp, daemon=True)
        arp_thread.start()
        
        # Start status update thread
        status_thread = threading.Thread(target=self.update_status, daemon=True)
        status_thread.start()

        try:
            while self.running:
                self.arp_scan()
                time.sleep(self.scan_interval)
        except Exception as e:
            self.running = False
            print(f"\n[!] Error: {str(e)}")

    def stop(self):
        self.running = False
