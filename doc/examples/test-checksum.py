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

    print "%03d: checksum=%04x, OK=%s" % (n, ip.checksum, ip.test_l3_cksm())
    if not ip.test_l3_cksm():
        ip.set_l3_cksm()
    else:
        ip.checksum = 0xCDEF
    print "     checksum=%04x, OK=%s" % (ip.checksum, ip.test_l3_cksm())

    tcp = ip.tcp
    if tcp:
        try:
            print "        tcp checksum=%04x, ok=%s" % (
                tcp.checksum, tcp.test_trans_cksm())
            if not tcp.test_trans_cksm():
                tcp.set_trans_cksm()
            else:
                tcp.checksum = 0x1234
            print "        tcp checksum=%04x, ok=%s" % (
                tcp.checksum, tcp.test_trans_cksm())
        except ValueError, e:
            print "        .tcp. %s" % e

    udp = ip.udp
    if udp:
        #continue
        try:
            # Only packet 236 is short enough for plt to check it's correct
            print "        udp checksum=%04x, ok=%s" % (
                udp.checksum, udp.test_trans_cksm())
            if not udp.test_trans_cksm():
                udp.set_trans_cksm()
            else:
                udp.checksum = 0x5678
            print "        udp checksum=%04x, ok=%s" % (
                udp.checksum, udp.test_trans_cksm())
        except ValueError, e:
            print "        .udp. %s" % e

    #if n == 20:
    #    break

print "%5d packets accepted" % (t.pkt_accepts())
print "%5d packets dropped" % (t.pkt_drops())

t.close()  # Don't do this inside the loop!
