import socket
import argparse
import sys
import codecs
import threading
import re

_tcp_timeout = 2
_udp_timeout = 2
_message_format = '{}: {} is a {} port'
_udp_payloads = {
    'dns': '000000000001000000000000095f7365727669636573075f646e732d7364045f756470056c6f63616c00000c0001',

    'snmp': '303a020103300f02024a69020300ffe30401040201030410300e04000'
            '20100020100040004000400301204000400a00c020237f00201000201003000',

    'ripv1': '010100000000000000000000000000000000000000000010',

    'nbns': '80f000100001000000000000'
    '20434b4141414141414141414141414141414141414141414141414141414141410000210001',

    'daytime': '0000000000010000000000000'
               '95f7365727669636573075f646e732d7364045f756470056c6f63616c00000c0001',

    'echo': '0d0a0d0a',

    'rpc+nfs': '000000000000000000000002000186a3000000020000000000000000000000000000000000000000',

    'quic': '16fefd000000000000000000360100002a000000000000002afefd000'
    '000007c77401e8ac822a0a018ff9308caac0a642fc92264bc08a81689193f00000002002f0100',

    'srvloc': '0201000036200000000000010002656e00000015736572766963653a736572766963652d6167656e74000764656661756c7400000000',
    'time': '000000000001000000000000095f7365727669636573075f646e732d7364045f756470056c6f63616c00000c0001',
}

def is_ip_address(string):
    return bool(re.match(r'^(\d+\.){3}\d+$', string))

def scan_port(args):
    for port in range(input_data['start'], input_data['end']):
        threading.Thread(target=scan_TCP, args=(args['host'], port)).start()
        local = threading.local().__dict__
        for proto in _udp_payloads:
            params = args['host'], port, proto, local
            threading.Thread(target=scan_UDP, args=params).start()

def scan_TCP(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.settimeout(_tcp_timeout)
            s.connect((host, port))
        except (socket.timeout, socket.error):
            pass
        else:
            print(_message_format.format(host, port, 'TCP'))


def scan_UDP(host, port, proto, local):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    host_name = host
    if not is_ip_address(host):
        host = socket.gethostbyaddr(host)[2][0]
    sock.settimeout(_udp_timeout)
    payload = _udp_payloads[proto]
    for i in range(1, 10):
        sock.sendto(codecs.decode(payload, 'hex'), (host, port))
    try:
        _, addr = sock.recvfrom(1024)
        if addr == (host, port) and not port in local:
            local[port] = proto
            print(_message_format.format(host_name, port, 'UDP'))
    except socket.timeout:
        pass


if __name__=='__main__':
    parser = argparse.ArgumentParser(description='''
        TCP/UDP port scanner
    ''')
    parser.add_argument('start',
                        type=int,
                        help='start of the range')
    parser.add_argument('end',
                        type=int,
                        help='end of the range')
    parser.add_argument('host',
                        type=str,
                        help='host name')
    input_data = parser.parse_args().__dict__
    scan_port(input_data)
