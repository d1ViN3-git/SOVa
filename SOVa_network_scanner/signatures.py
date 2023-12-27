from scapy.layers.inet import IP
from scapy.layers.inet import TCP
from scapy.layers.inet import UDP
from scapy.layers.inet import ICMP
import time
from logger import setup_logging
from post import send_post_request
logg = setup_logging()



#Обнаружение аномально большого количества пакетов от одного источника
packet_counts = {}
def detect_packet_flooding(packet):
    global packet_counts
    if packet.haslayer(IP):
        source_ip = packet[IP].src
        packet_counts[source_ip] = packet_counts.get(source_ip, 0) + 1
        if packet_counts[source_ip] > 800:
            packet_counts[source_ip] = 0
            name = "big_counts_of_packets_from_ip"
            desc = f"Обнаружено аномально большое количество пакетов от источника {source_ip}!"
            print(f"Обнаружено аномально большое количество пакетов от источника {source_ip}!")
            logg.info(f"{name}")
            send_post_request(source_ip, name, desc)




#Обнаружение аномального размера пакетов
def detect_packet_size_anomaly(packet):
    packet_size = len(packet)
    if packet.haslayer(IP):
        source_ip = packet[IP].src
        if packet_size > 10000:
            name = "big_size_of_packet"
            desc = "Обнаружен аномальный размер пакета!"
            print(f"Обнаружен аномальный размер пакета!")
            logg.info(f"{name}")
            send_post_request(source_ip, name, desc)



#Обнаружение аномальных интервалов между пакетами
# Последнее время прихода пакета от каждого источника
last_packet_time = {}
def detect_packet_spacing_anomaly(packet):
    global last_packet_time
    if packet.haslayer(IP):
        source_ip = packet[IP].src
        current_time = time.time()
    # Проверяем, если прошло менее 100 миллисекунд с момента последнего пакета от данного источника
        if source_ip in last_packet_time and current_time - last_packet_time[source_ip] < 0.001:
            name = "anomal_interval_of_time_between_packets"
            desc = f"Обнаружен аномальный интервал между пакетами от источника {source_ip}!"
            print(f"Обнаружен аномальный интервал между пакетами от источника {source_ip}!")
            logg.info(f"{name}")
            send_post_request(source_ip, name, desc)
            last_packet_time[source_ip] = current_time



#Обнаружение аномального количества соединений к определенному порту
port_connections = {}
def detect_port_connection_anomaly(packet):
    global port_connections
    if packet.haslayer(TCP):
        source_ip = packet[IP].src
        dst_port = packet[TCP].dport
        port_connections[dst_port] = port_connections.get(dst_port, 0) + 1
        # Проверка
        if port_connections[dst_port] > 400:
            name = "big_counts_of_connections_to_the_port"
            desc = f"Обнаружено аномально большое количество соединений к порту {dst_port}!"
            print(f"Обнаружено аномально большое количество соединений к порту {dst_port}!")
            logg.info(f"{name}")
            send_post_request(source_ip, name, desc)
            port_connections[dst_port] = 0


#Обнаружение аномального количества ICMP-пакетов от одного источника
icmp_packet_counts = {}
def detect_icmp_packet_flooding(packet):
    global icmp_packet_counts
    if packet.haslayer(ICMP):
        source_ip = packet[IP].src
        icmp_packet_counts[source_ip] = icmp_packet_counts.get(source_ip, 0) + 1
        if icmp_packet_counts[source_ip] > 100:
            name = "icmp_flood"
            desc = f"Обнаружено аномально большое количество ICMP-пакетов от источника {source_ip}!"
            print(f"Обнаружено аномально большое количество ICMP-пакетов от источника {source_ip}!")
            logg.info(f"{name}")
            send_post_request(source_ip,name, desc)
            icmp_packet_counts[source_ip] = 0



# Обнаружение аномального количества UDP-пакетов на определенном порту:
udp_port_packets = {}
def detect_udp_packet_anomaly(packet):
    if packet.haslayer(IP):
        if packet.haslayer(UDP):
            source_ip = packet[IP].src
            global udp_port_packets
            dst_port = packet[UDP].dport
            udp_port_packets[dst_port] = udp_port_packets.get(dst_port, 0) + 1
            if udp_port_packets[dst_port] > 400:
                name = "udp_flood_on_the_port"
                desc = f"Обнаружено аномально большое количество UDP-пакетов на порту {dst_port}!"
                print(f"Обнаружено аномально большое количество UDP-пакетов на порту {dst_port}!")
                logg.info(f"{name}")
                send_post_request(source_ip, name, desc)
                udp_port_packets[dst_port] = 0


#Обнаружение аномального количества UDP-пакетов с большим размером данных
max_udp_packet_size = 1500
def detect_large_udp_packets(packet):
    if packet.haslayer(IP):
        if packet.haslayer(UDP):
            source_ip = packet[IP].src
            udp_payload_len = len(packet[UDP].payload)
            if udp_payload_len > max_udp_packet_size:
                name = "big_size_of_udp_packet"
                desc = f"Обнаружен аномально большой UDP-пакет размером {udp_payload_len} байт!"
                print(f"Обнаружен аномально большой UDP-пакет размером {udp_payload_len} байт!")
                logg.info(f"{name}")
                send_post_request(source_ip, name, desc)


#SYN флуд
SYN_count = {}
def analyze_syn_traffic(packet):
    global SYN_count
    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        source_ip = packet[IP].src
        if source_ip in SYN_count:
            SYN_count[source_ip] += 1
        else:
            SYN_count[source_ip] = 1
        if SYN_count[source_ip] > 1000:  # Пороговое значение для аномального количества пакетов SYN
            name = "syn_flood"
            desc = f"Обнаружен SYN flood от {source_ip}!"
            print(f"Обнаружен SYN flood от {source_ip}!")
            logg.info(f"{name}")
            send_post_request(source_ip, name, desc)
            SYN_count[source_ip] = 0


#ping of death
def analyze_icmp(packet):
    if packet.haslayer(ICMP):
        icmp_type = packet[ICMP].type
        if icmp_type == 8:  # ICMP Echo Request (ping) тип 8
            packet_size = len(packet)
            if packet_size > 65535:
                source_ip = packet[IP].src
                name ="ping_of_death"
                desc = "Обнаружен ICMP ping of death"
                print("Обнаружен ICMP ping of death")
                logg.info(f"{name}")
                send_post_request(source_ip, name, desc)


#FIN RST
def analyze_tcp_flags(packet):
    if packet.haslayer(TCP):
        source_ip = packet[IP].src
        flags = packet[TCP].flags
        if flags & (0x04 | 0x01) == (0x04 | 0x01):
            name = "TCP_with_FIN_RST"
            desc = "Обнаружен TCP пакет с фалагами FIN RST"
            print("Обнаружен TCP пакет с фалагами FIN RST")
            logg.info(f"{name}")
            send_post_request(source_ip, name, desc)

