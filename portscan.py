import socket
import argparse
import sys
import threading

_tcp_timeout = 2
_udp_timeout = 2
_message_format = '{}: {} is a {} port'

def scan_port(args):
    threads = []
    for port in range(input_data['start'], input_data['end']):
        thread = threading.Thread(target=scan_TCP, args=(args['host'], port))
        thread.start()
        threads.append(thread)

def scan_TCP(host, port):

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.settimeout(_tcp_timeout)
            s.connect((host, port))
        except (socket.timeout, socket.error):
            pass
        else:
            print(_message_format.format(host, port, 'TCP'))

def scan_UDP(**args):

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as ping:
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
