#!/usr/bin/env python

# Thu, 13 Mar 14 (PDT)
# ip6.py:  Demonstrate IPv6 objects
# Copyright (C) 2015, Nevil Brownlee, U Auckland | WAND

from plt_testing import *

t = get_example_trace('anon-v4.pcap')

n = 0;  offset = 12
blanks = ' ' * (offset+5)
for pkt in t:
    n += 1  # Wireshark uses 1-org packet numbers
    if n == 11:
        break
    ip = pkt.ip    
    if not ip:
        continue

    l2 = pkt.layer2
    print "n=%3d, kind=%s, type=%s, size=%d, linktype=%d, ethertype=%04x" % (
        n, l2.kind, l2.type, l2.size, l2.linktype, l2.ethertype)

    print_data('Packet:', offset, pkt.data, 64)
    print "%s== kind=%s, type=%s" % (blanks, pkt.kind, pkt.type)

    l2data = l2.data
    print_data('L2 before:', offset, l2data, 64)

    l2data[0] = 0x55;  l2data[1] = 0x66;  l2data[2] = 0x77;
    l2.data = l2data  # Write new values into first three bytes
    print_data('L2 after:', offset, l2.data, 64)
    print "%s== kind=%s, type=%s" % (blanks, l2.kind, l2.type)

    l3 = pkt.layer3
    print_data('Layer3:', offset, l3.data, 64)
    print "%s== kind=%s, type=%s" % (blanks, l3.kind, l3.type)

    tr = pkt.transport
    print_data('Transport:', offset, tr.data, 64)
    print "%s== kind=%s, type=%s, proto=%d" % (
        blanks, tr.kind, tr.type, tr.proto)

    ipdata = ip.data
    print_data('IP:', offset, ipdata, 64)
    print "%s== kind=%s, type=%s, ip.proto=%d" % (
        blanks, ip.kind, ip.type, ip.proto)
    print

t.close()  # Don't do this inside the loop!

print "%d packets in trace\n" % (n)


