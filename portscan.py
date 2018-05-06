import socket
import argparse
import sys
import codecs
import threading
import re
import time
import os
import signal
from multiprocessing.pool import ThreadPool

_tcp_timeout = 2
_udp_timeout = 2
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

def cls():
    os.system('cls' if os.name == 'nt' else 'clear')

def is_ip_address(string):
    return bool(re.match(r'^(\d+\.){3}\d+$', string))

def scan_port(args):
        try:
            signal.signal(signal.SIGINT, lambda *_: quit())
            pool = ThreadPool(1000)
            jobs = []
            local = threading.local().__dict__
            start, end = input_data['start'], input_data['end']
            for port in range(start, end):
                jobs.append(pool.apply_async(scan_TCP, [args['host'], port, local]))
                for proto in _udp_payloads:
                    jobs.append(pool.apply_async(scan_UDP, [args['host'], port, proto, local]))
            pool.close()
            while not all(x.ready() for x in jobs):
                percent = round(100 * len([x for x in jobs if x.ready()]) / len(jobs), 2)
                print_with_progress(local, percent)
                time.sleep(1)
            print_with_progress(local, 100)
        except KeyboardInterrupt:
            quit()

def print_with_progress(local, percent):
    cls()
    print(f'Progress: {percent}% complete')
    for key, guess_proto in local.items():
        transport_proto, port = key
        print(f'Discovered {port} port on {transport_proto}', f'({guess_proto})' if guess_proto else '')

def scan_TCP(host, port, local):
    if ('tcp', port) in local:
        return
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.settimeout(_tcp_timeout)
            s.connect((host, port))
        except (socket.timeout, socket.error):
            pass
        else:
            local[('tcp', port)] = None


def scan_UDP(host, port, proto, local):
    if ('udp', port) in local:
        return
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if not is_ip_address(host):
        host = socket.gethostbyaddr(host)[2][0]
    sock.settimeout(_udp_timeout)
    payload = _udp_payloads[proto]
    for _ in range(1, 10):
        sock.sendto(codecs.decode(payload, 'hex'), (host, port))
    try:
        _, addr = sock.recvfrom(1024)
        if addr == (host, port):
            local[('udp', port)] = None
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
