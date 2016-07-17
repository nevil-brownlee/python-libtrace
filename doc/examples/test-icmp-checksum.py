#!/usr/bin/env python

# Thu, 13 Mar 14 (PDT)
# ip.py:  Demonstrate IP objects
# Copyright (C) 2015, Nevil Brownlee, U Auckland | WAND

from plt_testing import *

t = get_example_trace('icmp-sample.pcap')

n = 0
for pkt in t:
    n += 1  # Wireshark uses 1-org packet numbers
    ip = pkt.ip
    if not ip:
        continue

    print "%03d: checksum=%04x, OK=%s" % (n, ip.checksum, ip.test_l3_cksm())

    icmp = ip.icmp
    if icmp:
        try:
            print "        icmp checksum=%04x, ok=%s" % (
                icmp.checksum, icmp.test_trans_cksm())
            if not icmp.test_trans_cksm():
                icmp.set_trans_cksm()
            else:
                icmp.checksum = 0x5678
            print "        icmp checksum=%04x, ok=%s" % (
                icmp.checksum, icmp.test_trans_cksm())
        except ValueError, e:
            print "        .icmp. %s" % e

    if n == 10:
        break

t.close()


t = get_example_trace('icmp6-sample.pcap')

n = 0
for pkt in t:
    n += 1  # Wireshark uses 1-org packet numbers
    ip6 = pkt.ip6
    if not ip6:
        continue

    print "%03d: checksum=%04x, OK=%s" % (n, ip.checksum, ip.test_trans_cksm())

    icmp6 = ip6.icmp6
    if icmp6:
        try:
            print "        icmp6 checksum=%04x, ok=%s" % (
                icmp6.checksum, icmp6.test_trans_cksm())
            if not icmp6.test_trans_cksm():
                icmp6.set_trans_cksm()
            else:
                icmp6.checksum = 0x9ABC
            print "        icmp6 checksum=%04x, ok=%s" % (
                icmp6.checksum, icmp6.test_trans_cksm())
        except ValueError, e:
            print "        .icmp6. %s" % e

    if n == 10:
        break

t.close()

