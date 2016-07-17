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
            print "%3d     tcp checksum=%04x, ok=%s" % (
                n, tcp.checksum, tcp.checksum_ok())
            if not tcp.checksum_ok():
                tcp.set_checksum()
            else:
                tcp.checksum = 0x1234
            print "        tcp checksum=%04x, ok=%s" % (
                tcp.checksum, tcp.checksum_ok())
        except ValueError, e:
            print "        .tcp. %s" % e

    udp = ip6.udp
    if udp:
        try:
            print "%3d     udp checksum=%04x, ok=%s" % (
                n, udp.checksum, udp.checksum_ok())
            if not udp.checksum_ok():
                udp.set_checksum()
            else:
                udp.checksum = 0x5678
            print "        udp checksum=%04x, ok=%s" % (
                udp.checksum, udp.checksum_ok())
        except ValueError, e:
            print "        .udp. %s" % e

    icmp6 = ip6.icmp6
    if icmp6:
        try:
            print "%3d     icmp6 checksum=%04x, ok=%s" % (
                n, icmp6.checksum, icmp6.checksum_ok())
            if not icmp6.checksum_ok():
                icmp6.set_checksum()
            else:
                icmp6.checksum = 0x9abc
            print "        icmp6 checksum=%04x, ok=%s" % (
                icmp6.checksum, icmp6.checksum_ok())
        except ValueError, e:
            print "        .icmp6. %s" % e

    #if n == 5:
    #    break

print "%5d packets accepted" % (t.pkt_accepts())
print "%5d packets dropped" % (t.pkt_drops())

t.close()  # Don't do this inside the loop!
