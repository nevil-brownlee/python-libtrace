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

    #print "%03d: checksum=%04x, OK=%s" % (n, ip.checksum, ip.test_l3_cksm())
    test_println("   %03d: checksum=%04x, OK=%s" % (n, ip.checksum, ip.test_l3_cksm()), get_tag("n:"+str(n)))

    icmp = ip.icmp
    if icmp:
        try:
            test_println("        icmp checksum=%04x, ok=%s" % (
                icmp.checksum, icmp.test_trans_cksm()), get_tag("n:"+str(n)))
            if not icmp.test_trans_cksm():
                icmp.set_trans_cksm()
            else:
                icmp.checksum = 0x5678
            test_println("        icmp checksum=%04x, ok=%s" % (
                icmp.checksum, icmp.test_trans_cksm()), get_tag("n:"+str(n)))
        except ValueError, e:
            test_println("        .icmp. %s" % e, get_tag("n:"+str(n)))

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
    test_println("   %03d: checksum_OK=%s" % (n, ip6.test_trans_cksm()), get_tag("n:"+str(n)))
    icmp6 = ip6.icmp6
    if icmp6:
        try:
            test_println("        icmp6 checksum=%04x, ok=%s" % (
                icmp6.checksum, icmp6.test_trans_cksm()), get_tag("n:"+str(n)))
            if not icmp6.test_trans_cksm():
                icmp6.set_trans_cksm()
            else:
                icmp6.checksum = 0x9ABC
            test_println("        icmp6 checksum=%04x, ok=%s" % (
                icmp6.checksum, icmp6.test_trans_cksm()), get_tag("n:"+str(n)))
        except ValueError, e:
            test_println("        .icmp6. %s" % e, get_tag("n:"+str(n)))

    if n == 10:
        break

t.close()

