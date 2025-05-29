from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, ARP
from collections import defaultdict, deque
import threading
import time

class NetworkMonitor:
    def __init__(self):
        self.traffic_data = defaultdict(lambda: {"packets": 0, "bytes": 0})
        self.traffic_log = deque(maxlen=1000)
        self.lock = threading.Lock()

    def analyze_packet(self, packet):
        if IP in packet:
            proto = "OTHER"
            port = "-"
            
            if TCP in packet:
                dport = packet[TCP].dport
                if dport == 443:
                    proto = "HTTPS"

                elif dport == 80:
                    proto = "HTTP"
                elif dport == 22:
                    proto = "SSH"
                elif dport == 53:
                    proto = "DNS"
                elif dport == 21:
                    proto = "FTP"
                elif dport == 25:
                    proto = "SMTP"
                elif dport == 110:
                    proto = "POP3"

                elif dport == 143:
                    proto = "IMAP"
                elif dport == 3389:
                    proto = "RDP"
                elif dport == 8080:
                    proto = "HTTP-ALT"
                elif dport == 3306:
                    proto = "MySQL"
                elif dport == 6379:
                    proto = "Redis"
                elif dport == 27017:
                    proto = "MongoDB"
                elif dport == 5000:
                    proto = "Flask"
                elif dport == 5001:
                    proto = "Flask-Alt"
                elif dport == 5002:
                    proto = "Flask-Alt2"
                elif dport == 5003: 
                    proto = "Flask-Alt3"
                elif dport == 5004:
                    proto = "Flask-Alt4"
                elif dport == 5005:
                    proto = "Flask-Alt5"
                elif dport == 5006:
                    proto = "Flask-Alt6"
                elif dport == 5007:
                    proto = "Flask-Alt7"
                elif dport == 5008:
                    proto = "Flask-Alt8"
                elif dport == 5009:
                    proto = "Flask-Alt9"
                elif dport == 5010:
                    proto = "Flask-Alt10"
                elif dport == 5011:
                    proto = "Flask-Alt11"
                elif dport == 5012:
                    proto = "Flask-Alt12"
                else:
                    proto = "TCP"
                port = dport

            elif UDP in packet:
                proto = "UDP"
                port = packet[UDP].dport

            elif ICMP in packet:
                proto = "ICMP"

            elif DNS in packet:
                proto = "DNS"

            elif ARP in packet:
                proto = "ARP"
              

            src = packet[IP].src
            dst = packet[IP].dst
            pkt_len = len(packet)
            key = (src, dst, proto, port)

            with self.lock:
                self.traffic_data[key]["packets"] += 1
                self.traffic_data[key]["bytes"] += pkt_len

                self.traffic_log.append({
                    "timestamp": time.time(),
                    "source_ip": src,
                    "dest_ip": dst,
                    "protocol": proto,
                    "port": str(port),
                    "packets": 1,
                    "bytes": pkt_len,
                    "status": "High" if pkt_len > 1000 else "Normal",
                    "action": "Logged"
                })

    def start_sniffing(self):
        sniff(prn=self.analyze_packet, store=0)

    def start(self):
        sniff_thread = threading.Thread(target=self.start_sniffing, daemon=True)
        sniff_thread.start()

    def get_stats(self):
        """Return summary statistics (aggregated traffic by IP, protocol, port)"""
        with self.lock:
            return [
                {
                    "source_ip": src,
                    "dest_ip": dst,
                    "protocol": proto,
                    "port": str(port),
                    "packets": stats["packets"],
                    "bytes": stats["bytes"],
                    "status": "High" if stats["packets"] > 100 else "Normal",
                    "action": "Logged"
                }
                for (src, dst, proto, port), stats in self.traffic_data.items()
            ]

    def get_latest_packets(self, count=10, offset=0):
        """Return the latest `count` packet logs (in reverse time order)"""
        with self.lock:
            return list(self.traffic_log)[::-1][offset:offset + count]
