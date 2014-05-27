#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import struct


def checksum(msg):
    msg_short_len = len(msg) // 2 * 2
    total = 0
    for i in range(0, msg_short_len, 2):
        total += (ord(msg[i + 1]) << 8) + ord(msg[i])
    if len(msg) % 2 != 0:
        total += ord(msg[-1])
    while (total >> 16) > 0:
        total = (total & 0xffff) + (total >> 16)
    total = total >> 8 | (total << 8 & 0xff00)
    return ~total & 0xffff

if __name__ == '__main__':
    IPPROTO_ICMP = socket.getprotobyname('icmp')
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, IPPROTO_ICMP)
    icmp_header = struct.pack('!BBHHH', 8, 0, 0, 1, 1)
    icmp_payload = 'Hello, World!'
    
#    csum = checksum(icmp_header + icmp_payload)
    icmp_header = struct.pack('!BBHHH', 8, 0, csum, 1, 1)
    packet = icmp_header + icmp_payload
    while packet:
        sent_bytes = sock.sendto(packet, ('www.google.co.jp', 0))
        packet = packet[sent_bytes:]