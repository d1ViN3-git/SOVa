import os
import sys
from scapy.layers.inet import IP
from scapy.layers.inet import TCP
from scapy.layers.inet import UDP
from scapy.layers.inet import ICMP
from post import get_interface_ip
from scapy.all import sniff
from signatures import *
from logger import setup_logging
logger = setup_logging()

def packet_callback(packet):
    detect_packet_flooding(packet)
    detect_packet_size_anomaly(packet)
    detect_packet_spacing_anomaly(packet)
    detect_port_connection_anomaly(packet)
    detect_icmp_packet_flooding(packet)
    detect_udp_packet_anomaly(packet)
    detect_large_udp_packets(packet)
    analyze_syn_traffic(packet)
    analyze_icmp(packet)
    analyze_tcp_flags(packet)
def sniff_incoming_packets(interface):
    filter_str = f"src host not {get_interface_ip(interface)} and (ip or tcp or udp or icmp)"
    sniff(iface = interface, filter = filter_str, prn = packet_callback)

while (True):
    logger.info("Start of network scanner")
    sniff_incoming_packets(f"{sys.argv[1]}")