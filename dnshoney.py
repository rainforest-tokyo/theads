#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import json
import ipaddress

from scapy.all import *
from netfilterqueue import NetfilterQueue

from Logger import Logger

def fake_dns_reply(pkt, qname):
    ip = IP()
    udp = UDP()
    ip.src = pkt[IP].dst
    ip.dst = pkt[IP].src
    udp.sport = pkt[UDP].dport
    udp.dport = pkt[UDP].sport

    solved_ip = "127.0.0.1"
    qd = pkt[UDP].payload
    dns = DNS(id = qd.id, qr = 1, qdcount = 1, ancount = 1, arcount = 1, nscount = 1, rcode = 0)
    dns.qd = qd[DNSQR]
    dns.an = DNSRR(rrname = qname, ttl = 257540, rdlen = 4, rdata = solved_ip)
    dns.ns = DNSRR(rrname = qname, ttl = 257540, rdlen = 4, rdata = solved_ip)
    dns.ar = DNSRR(rrname = qname, ttl = 257540, rdlen = 4, rdata = solved_ip)
    send(ip/udp/dns)

def dnshoney(pkt):
    global logger

    packet = IP(pkt.get_payload())
    print(packet)
    proto = packet.proto

    if proto is 0x11:
        # Check if it is a DNS packet (raw check)
        if packet[UDP].dport is 53:
            pkt.drop()
            dns = packet[UDP].payload
            qname = dns[DNSQR].qname

            data = {"ip":packet.src, "qname":qname}
            print( data )
            sys.stdout.flush()
            logger.log( data )

            fake_dns_reply(packet, qname)
        else :
            pkt.accept()
    else:
        pkt.accept()
        pass
#----------------------------

def main(argv) :
    global logger

    print( '#### START ####' )
    sys.stdout.flush()
    logger = Logger("/var/log/theads.log", False)

    nfqueue = NetfilterQueue()
    nfqueue.bind(2, dnshoney)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print('')

    nfqueue.unbind()

if __name__ == '__main__':
    main(sys.argv)

