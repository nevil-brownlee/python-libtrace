#!/usr/bin/env python

# Thu, 13 Mar 14 (PDT)
# sw-filter.py: Prints udp records from a trace
# Copyright (C) 2015, Nevil Brownlee, U Auckland | WAND

from plt_testing import *

t = get_example_trace('anon-v4.pcap')

n = nfp = 0;  offset = 12
for pkt in t:
    n += 1

    if pkt.udp and (pkt.udp.src_port == 53 or pkt.udp.dst_port == 53):
        nfp += 1

        print "%4d:" % (n),
        print_udp(pkt.udp, offset)
        print

        if nfp == 4:
            break

print "%d raw -> %d filtered packets" % (n, nfp)
