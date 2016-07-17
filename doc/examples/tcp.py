#!/usr/bin/env python

# Thu, 13 Mar 14 (PDT)
# tcp.py:  Demonstrate TCP objects
# Copyright (C) 2015, Nevil Brownlee, U Auckland | WAND

from plt_testing import *

t = get_example_trace('anon-v4.pcap')

n = 0
for pkt in t:
    tcp = pkt.tcp
    n += 1  # Wireshark uses 1-org packet numbers
    if not tcp:
        continue

    print "%5d:" % (n),
    print_tcp(tcp, 12)
    print
    if n == 20:
        break

t.close()  # Don't do this inside the loop!





