import sys
import ipaddress
import struct
import os
import socket
import threading
import time
import argparse
import logging


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
class IP:
    def __init__(self, buff=None):
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF

        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        # IP-адреса понятные человеку
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # сопоставляем константы протоколов с их названием
        self.protocol_map = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            logging.error(f'{e} No protocol for {self.protocol_num}')
            self.protocol = str(self.protocol_num)


class ICMP:
    def __init__(self, raw_header):
        if not raw_header:
            raise ValueError("Empty ICMP header")
        self.type = raw_header[0]
        self.code = raw_header[1]
        self.checksum = int.from_bytes(raw_header[2:4], byteorder='big')

def udp_sender(message, subnet):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        logging.info(f"На новые подключенные устр-ва будет отправлено сообщение '{message}'")
        for ip in ipaddress.ip_network(subnet).hosts():
            sender.sendto(bytes(message, 'utf-8'), (str(ip), 65212))
class Scanner:
    def __init__(self, host):
        self.host = host
        if os.name == 'nt':
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        self.socket.bind((host, 0))
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        if os.name == 'nt':
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    def sniff(self, message, subnet):
        host_up = set([f'{str(self.host)} *'])
        try:
            while True:
                # Читаем пакет
                raw_buffer = self.socket.recvfrom(65535)[0]
                ip_header = IP(raw_buffer[0:20])
                # Нас интересует ICMP-заголовок из пакета
                if ip_header.protocol == "ICMP":
                    # Определяем где находится ICMP пакет
                    offset = ip_header.ihl * 4
                    buf = raw_buffer[offset:offset + 8]
                    # Создаем структуру ICMP
                    icmp_header = ICMP(buf)
                    # ищем тип и код 3
                    if icmp_header.type == 3 and icmp_header.code == 3:
                        if ipaddress.ip_address(ip_header.src_address) in ipaddress.IPv4Network(subnet):
                            # Проверяем, содержит ли буфер наше слово
                            if raw_buffer[len(raw_buffer) - len(message):] == bytes(message, 'utf-8'):
                                tgt = str(ip_header.src_address)
                                if tgt != self.host and tgt not in host_up:
                                    host_up.add(str(ip_header.src_address))
                                    logging.info(f'Host Up: {tgt}')
        except KeyboardInterrupt:
            # если мы в Windows, выключаем неизбирательный режим
            if os.name == 'nt':
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            logging.info('User interrupted.')

        if host_up:
            logging.info(f'\n\nSummary: Hosts up on {subnet}')
        for host in sorted(host_up):
            logging.info(f'{host}')
        logging.info('')
        sys.exit()
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='UDP Sniffer and Sender')
    parser.add_argument('--subnet', type=str, required=True, help='Subnet in CIDR notation (e.g., 10.0.0.0/24)')
    parser.add_argument('--message', type=str, required=True, help='Message to send')
    parser.add_argument('--host', type=str, default='10.0.0.101', help='Host IP address to bind to')

    args = parser.parse_args()

    s = Scanner(args.host)
    time.sleep(1)
    t = threading.Thread(target=udp_sender, args=(args.message, args.subnet))
    t.start()
    s.sniff(args.message, args.subnet)