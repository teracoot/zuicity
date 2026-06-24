#!/usr/bin/env python3
"""TCP+UDP echo server used as the forward target inside the server namespace."""
import socket
import sys
import threading
import time

ip = sys.argv[1]
tcp_port = int(sys.argv[2])
udp_port = int(sys.argv[3])


def _handle(conn):
    with conn:
        while True:
            data = conn.recv(65536)
            if not data:
                break
            conn.sendall(data)


def tcp_echo():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, tcp_port))
    s.listen(16)
    while True:
        try:
            conn, _ = s.accept()
        except OSError:
            break
        threading.Thread(target=_handle, args=(conn,), daemon=True).start()


def udp_echo():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, udp_port))
    while True:
        data, addr = s.recvfrom(65536)
        s.sendto(data, addr)


threading.Thread(target=tcp_echo, daemon=True).start()
threading.Thread(target=udp_echo, daemon=True).start()
print(f"echo ready tcp={ip}:{tcp_port} udp={ip}:{udp_port}", flush=True)
while True:
    time.sleep(3600)
