#!/usr/bin/env python

# Thu, 13 Mar 14 (PDT)
# icmp.py: Demonstrate ICMP (v4) header decodes
# Copyright (C) 2015, Nevil Brownlee, U Auckland | WAND

from plt_testing import *

t = get_example_trace('icmp-sample.pcap')

n = 0;  nicmp = 0
offset = 12

for pkt in t:
    n += 1

    icmp = pkt.icmp
    if not icmp:
        continue

    test_println("%5d: " % (n), get_tag())
    print_icmp(icmp, offset, get_tag("n:"+str(n)))
    test_println('')

    nicmp += 1
    #if nicmp == 10:
    #    break

t.close

test_println(" %d packets examined\n" % (n), get_tag())
