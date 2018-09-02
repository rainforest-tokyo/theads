#!/usr/bin/env python
# -*- coding: utf-8 -*-

#-----------------------------------
# theads 
#
# Copyright (c) 2018 RainForest
#
# This software is released under the MIT License.
# http://opensource.org/licenses/mit-license.php
#-----------------------------------

import os
import json
import ipaddress

from scapy.all import *
from netfilterqueue import NetfilterQueue

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
    print "Sending the fake DNS reply to %s:%s" % (ip.dst, udp.dport)
    send(ip/udp/dns)

def dnshoney(pkt):
    packet = IP(pkt.get_payload())
    pkt.drop()

    if proto is 0x11:
        # Check if it is a DNS packet (raw check)
        if pkt[UDP].dport is 53:
            print "It's a DNS request"
            #dns = pkt[UDP].payload
            #qname = dns[DNSQR].qname
            #print "Sir Ping is requesting for %s" % qname
            #fake_dns_reply(pkt, qname)
    else:
        print "Protocol not handled!!"
        pass
#----------------------------

if __name__ == '__main__':
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, dnshoney)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print('')

    nfqueue.unbind()

