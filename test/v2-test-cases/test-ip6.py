#!/usr/bin/env python

# Thu, 13 Mar 14 (PDT)
# ip6.py:  Demonstrate IPv6 objects
# Copyright (C) 2015, Nevil Brownlee, U Auckland | WAND

from plt_testing import *

t = get_example_trace('anon-v6.pcap')

n = 0
for pkt in t:
    ip6 = pkt.ip6
    if not ip6:
        continue
    n += 1  # Wireshark uses 1-org packet numbers

    test_println("%5d: " % (n), get_tag())
    print_ip6(ip6, 12, get_tag("n:"+str(n)))
    test_println('')
    if n == 20:
        break

t.close()  # Don't do this inside the loop!

