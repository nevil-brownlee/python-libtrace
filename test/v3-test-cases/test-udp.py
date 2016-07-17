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

    test_println("%4d:" % (n), get_tag())
    print_udp(udp, offset, get_tag("n:"+str(n)))
    test_println('')

    if n == 20:
        break

t.close

test_println("%d packets examined\n" % (n), get_tag())
