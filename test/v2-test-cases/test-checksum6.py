#!/usr/bin/env python

# Copyright (C) 2015, Nevil Brownlee, U Auckland | WAND

from plt_testing import *

#t = get_example_trace('icmp6-sample.pcap')
t = get_example_trace('anon-v6.pcap')

n = 0
for pkt in t:
    n += 1  # Wireshark uses 1-org packet numbers
    ip6 = pkt.ip6
    if not ip6:
        continue

    tcp = ip6.tcp
    if tcp:
        try:
            test_println("%3d     tcp checksum=%04x, ok=%s" % (
                n, tcp.checksum, tcp.test_trans_cksm()), get_tag("n:"+str(n)))
            if not tcp.test_trans_cksm():
                tcp.set_trans_cksm()
            else:
                tcp.checksum = 0x1234
            test_println("        tcp checksum=%04x, ok=%s" % (
                tcp.checksum, tcp.test_trans_cksm()), get_tag("n:"+str(n)))
        except ValueError, e:
            test_println("        .tcp. %s" % e, get_tag("n:"+str(n)))

    udp = ip6.udp
    if udp:
        try:
            test_println("%3d     udp checksum=%04x, ok=%s" % (
                n, udp.checksum, udp.test_trans_cksm()), get_tag("n:"+str(n)))
            if not udp.test_trans_cksm():
                udp.set_trans_cksm()
            else:
                udp.checksum = 0x5678
            test_println("        udp checksum=%04x, ok=%s" % (
                udp.checksum, udp.test_trans_cksm()), get_tag("n:"+str(n)))
        except ValueError, e:
            test_println("        .udp. %s" % e, get_tag("n:"+str(n)))

    icmp6 = ip6.icmp6
    if icmp6:
        try:
            test_println("%3d     icmp6 checksum=%04x, ok=%s" % (
                n, icmp6.checksum, icmp6.test_trans_cksm()), get_tag("n:"+str(n)))
            if not icmp6.test_trans_cksm():
                icmp6.set_trans_cksm()
            else:
                icmp6.checksum = 0x9abc
            test_println("        icmp6 checksum=%04x, ok=%s" % (
                icmp6.checksum, icmp6.test_trans_cksm()), get_tag("n:"+str(n)))
        except ValueError, e:
            test_println("        .icmp6. %s" % e, get_tag("n:"+str(n)))

    #if n == 5:
    #    break

test_println("%5d packets accepted" % (t.pkt_accepts()), get_tag())
test_println("%5d packets dropped" % (t.pkt_drops()), get_tag())

t.close()  # Don't do this inside the loop!
