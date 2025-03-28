import socket
import struct
import threading
import time
import ipaddress
import os
import sys


SUBNET: str = "10.0.0.0/24"
MESSAGE: str = "I'm Java-warrior"

class IP:
    def __init__(self, buff = None):        #Инциализация экземпляров класса IP
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

        #Байтовые ip-адреса в человекочитаемый формат
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        #Определение протокола по номеру
        self.protocol_map = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print('%s No protocol for %s' % (e, self.protocol_num))
            self.protocol = str(self.protocol_num)

class ICMP:
    def __init__(self, buff):
        header = struct.unpack('BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]

#Отправка UDP-пакетов с сообщением
def udp_sender():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:   #создание сокет: socket.AF_INET- исп-ся ipv4; socket.SOCK_DGRAM - сокет исп-ет протокол UDP
        for ip in ipaddress.ip_network(SUBNET).hosts():
            sender.sendto(bytes(MESSAGE, 'utf-8'), (str(ip), 65212))

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

    def sniff(self):
        host_up = set([f'{str(self.host)} *'])
        try:
            while True:

                # Читаем пакет
                raw_buffer = self.socket.recvfrom(65535)[0]

                # создаем IP-заголовок из первых 20 байтов
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
                        if ipaddress.ip_address(ip_header.src_address) in ipaddress.IPv4Network(SUBNET):
                            # Проверяем, содержит ли буфер наше слово
                            if raw_buffer[len(raw_buffer) - len(MESSAGE):] == bytes(MESSAGE, 'utf-8'):
                                tgt = str(ip_header.src_address)
                                if tgt != self.host and tgt not in host_up:
                                    host_up.add(str(ip_header.src_address))
                                    print(f'Host Up: {tgt}')

        except KeyboardInterrupt:
            if os.name == 'nt':
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            print('\nUser interrupted.')

        if host_up:
            print(f'\n\nSummary: Hosts up on {SUBNET}')
        for host in sorted(host_up):
            print(f'{host}')
        print('')
        sys.exit()

if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = '10.0.0.101'

    s = Scanner(host)

    time.sleep(1)
    t = threading.Thread(target=udp_sender)
    t.start()
    s.sniff()
