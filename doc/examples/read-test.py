#!/usr/bin/env python

# Thu, 13 Mar 14 (PDT)
# icmp.py: Demonstrate ICMP (v4) header decodes
# Copyright (C) 2015, Nevil Brownlee, U Auckland | WAND

from plt_testing import *

t = get_example_trace('icmp-sample.pcap')

n = 0;  nicmp = 0
offset = 12

p = plt.packet()
while True:
    if not t.read_packet(p):
        break
    n += 1

    icmp = p.icmp
    if not icmp:
        continue

    print "%5d: " % (n),
    print_icmp(icmp, offset)
    print

    nicmp += 1
    #if nicmp == 10:
    #    break

t.close

print "%d packets examined\n" % (n)
