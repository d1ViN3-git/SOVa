#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <interface> <ip_address>"
    exit 1
fi

interface="$1"
ip_address="$2"

# Создание содержимого файла scanner.service
service_content="[Unit]
Description=network scanner
After=network.target

[Service]
User=root
Group=root
Restart=always
ExecStart=/usr/bin/python3 /home/user/PycharmProjects/sov/scaner.py $interface $ip_address

[Install]
WantedBy=multi-user.target"

service_file="/etc/systemd/system/scanner.service"
echo "$service_content" | sudo tee "$service_file" > /dev/null

systemctl daemon-reload
systemctl start scanner
systemctl status scanner
