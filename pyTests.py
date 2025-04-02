import pytest
import ipaddress
from main import IP, ICMP

def test_ip_parsing():
    #Проверка парсинга IP-заголовка.
    raw_ip_header = b'\x45\x00\x00\x3c\x1c\x46\x40\x00\x40\x06\xa6\xec\xc0\xa8\x01\x02\xc0\xa8\x01\x01'
    ip_header = IP(raw_ip_header)

    assert str(ip_header.src_address) == "192.168.1.2"
    assert ip_header.protocol == "TCP"

def test_icmp_parsing():
    raw_icmp_header = b'\x03\x03\xf4\x1a\x00\x01'
    icmp_header = ICMP(raw_icmp_header)

    assert icmp_header.type == 3
    assert icmp_header.code == 3

def test_icmp_checksum():
    raw_header = b'x08x00x1cx46x00x01x00x01' #заголовок с известной контрольной суммой
    icmp_header = ICMP(raw_header)
    assert icmp_header.checksum == 14456

def test_empty_icmp_header():
    try:
        icmp_header = ICMP(b'')  # Пустой заголовок
    except ValueError as e:
        assert str(e) == "Empty ICMP header"
    else:
        pytest.fail("Esception not thrown")  # Если исключение не возникло, тест провалится
