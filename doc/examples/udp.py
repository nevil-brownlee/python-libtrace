#!/usr/bin/env python

# Thu, 13 Mar 14 (PDT)
# udp.py:  Demonstrate UDP objects
# Copyright (C) 2015, Nevil Brownlee, U Auckland | WAND

from plt_testing import *

t = get_example_trace('anon-v4.pcap')

n = 0;  offset = 12
for pkt in t:
    udp = pkt.udp
    if not udp:
        continue
    n += 1

    print "%4d:" % (n),
    print_udp(udp, offset)
    print

    if n == 20:
        break

t.close

print "%d packets examined\n" % (n)
