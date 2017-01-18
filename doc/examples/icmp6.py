#!/usr/bin/env python

# Sun, 23 Oct 2016 (NZDT)
# icmp6.py: Demonstrate ICMP (v4) header decodes
# Copyright (C) 2017, Nevil Brownlee, U Auckland | WAND

from plt_testing import *

t = get_example_trace('icmp6-sample.pcap')

n = 0;  nicmp = 0
offset = 12

for pkt in t:
    n += 1

    icmp6 = pkt.icmp6
    if not icmp6:
        continue

    print "%5d: " % (n),
    print_icmp6(icmp6, offset)
    print

    nicmp += 1
    #if nicmp == 10:
    #    break

t.close

print "%d packets examined\n" % (n)
