import unittest
from unittest.mock import patch, MagicMock
import socket
import ipaddress

from main import IP, ICMP, Scanner


class TestIP(unittest.TestCase):
    def setUp(self):
        self.raw_ip_header = b'x45x00x00x3cx1cx46x40x00x40x06xb1xe6xc0xa8x00x68xc0xa8x00x01'  #заголовок в байтовом формате
        self.ip = IP(self.raw_ip_header)

    def test_ip_address(self):
        self.assertEqual(str(self.ip.src_address), '10.0.0.1')
        self.assertEqual(str(self.ip.dst_address), '10.0.0.101')

    def test_protocol(self):
        self.assertEqual(self.ip.protocol, 'TCP')

class TestICMP(unittest.TestCase):
    def setUp(self):
        self.raw_icmp_header = b'x00x00x00x01x00x01x00x00'  #заголовок в байтовом формате
        self.icmp = ICMP(self.raw_icmp_header)

    def test_icmp_type(self):
        self.assertEqual(self.icmp.type, 0)  # Тип ICMP в примере Echo Reply

class TestScanner(unittest.TestCase):
    @patch('socket.socket')
    def setUp(self, mock_socket):
        self.mock_socket = mock_socket.return_value
        self.scanner = Scanner('10.0.0.101', '255.255.255.0')

    @patch('socket.socket.recvfrom')
    def test_sniff_host_up(self, mock_recvfrom):
        # Настройка для имитации получения пакета
        mock_recvfrom.return_value = (b'x45x00x00x3cx1cx46x40x00x40x06xb1xe6xc0xa8x00x68xc0xa8x00x01' + b'Hello', ('10.0.0.101', 0))

        # Запуск метода
        self.scanner.sniff('Hello', '192.168.0.0/24')

        # Проверка, что сокет был вызван
        self.mock_socket.recvfrom.assert_called()

if __name__ == '__main__':
    unittest.main()