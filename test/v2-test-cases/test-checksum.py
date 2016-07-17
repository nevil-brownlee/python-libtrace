#!/usr/bin/env python

# Thu, 13 Mar 14 (PDT)
# ip.py:  Demonstrate IP objects
# Copyright (C) 2015, Nevil Brownlee, U Auckland | WAND

from plt_testing import *

t = get_example_trace('anon-v4.pcap')

n = 0
for pkt in t:
    n += 1  # Wireshark uses 1-org packet numbers
    ip = pkt.ip
    if not ip:
        continue

    test_println("   %03d: checksum=%04x, OK=%s" % (n, ip.checksum, ip.test_l3_cksm()), get_tag())
    if not ip.test_l3_cksm():
        ip.set_l3_cksm()
    else:
        ip.checksum = 0xCDEF
    test_println("     checksum=%04x, OK=%s" % (ip.checksum, ip.test_l3_cksm()), get_tag("n:"+str(n)))

    tcp = ip.tcp
    if tcp:
        try:
            test_println("        tcp checksum=%04x, ok=%s" % (
                tcp.checksum, tcp.test_trans_cksm()), get_tag("n:"+str(n)))
            if not tcp.test_trans_cksm():
                tcp.set_trans_cksm()
            else:
                tcp.checksum = 0x1234
            test_println("        tcp checksum=%04x, ok=%s" % (
                tcp.checksum, tcp.test_trans_cksm()), get_tag("n:"+str(n)))
        except ValueError, e:
            test_println("        .tcp. %s" % e, get_tag("n:"+str(n)))

    udp = ip.udp
    if udp:
        #continue
        try:
            # Only packet 236 is short enough for plt to check it's correct
            test_println("        udp checksum=%04x, ok=%s" % (
                udp.checksum, udp.test_trans_cksm()), get_tag("n:"+str(n)))
            if not udp.test_trans_cksm():
                udp.set_trans_cksm()
            else:
                udp.checksum = 0x5678
            test_println("        udp checksum=%04x, ok=%s" % (
                udp.checksum, udp.test_trans_cksm()), get_tag("n:"+str(n)))
        except ValueError, e:
            test_println("        .udp. %s" % e, get_tag("n:"+str(n)))

    #if n == 20:
    #    break

test_println("%5d packets accepted" % (t.pkt_accepts()), get_tag())
test_println("%5d packets dropped" % (t.pkt_drops()), get_tag())

t.close()  # Don't do this inside the loop!
