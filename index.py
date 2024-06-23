from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
import sys

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        print(f"IP Packet: {ip_src} -> {ip_dst}, Protocol: {proto}")

        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            print(f"TCP Packet: {ip_src}:{sport} -> {ip_dst}:{dport}")
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            print(f"UDP Packet: {ip_src}:{sport} -> {ip_dst}:{dport}")

def main(interface):
    print(f"Starting packet capture on interface {interface}")
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <interface>")
        sys.exit(1)
    
    interface = sys.argv[1]
    main(interface)
