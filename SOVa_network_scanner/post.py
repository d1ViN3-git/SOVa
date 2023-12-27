import requests
from datetime import datetime
import socket
import json
import fcntl
import struct
import sys
def get_interface_ip(interface):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ip_address = socket.inet_ntoa(fcntl.ioctl(
            sock.fileno(),
            0x8915,
            struct.pack('256s', interface[:15].encode("utf-8"))
        )[20:24])
        return ip_address
    except IOError:
        return None

def send_post_request(attack_ip, name, description):
    curr_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    interface = f"{sys.argv[1]}"
    local_ip = get_interface_ip(interface)
    json_data = {
        "date": curr_time,
        "point": local_ip,
        "module": "network_scanner",
        "data": f'''{{
            "attack_ip": "{attack_ip}",
            "name": "{name}",
            "description": "{description}"
        }}'''
    }
    json_payload = json.dumps(json_data)
    #print(json_payload)
    headers = {
        "Content-Type": "application/json"
    }
    response = requests.post(f"http://{sys.argv[2]}:5000/v1/api/sib", data=json_payload, headers=headers)

    # Проверка статуса ответа
    if response.status_code == 200:
        print("Запрос успешно выполнен.")
    else:
        print(f"Ошибка при выполнении запроса: {response.status_code}")