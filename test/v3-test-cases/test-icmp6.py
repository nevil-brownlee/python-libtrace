#!/usr/bin/env python

# Thu, 13 Mar 14 (PDT)
# icmp6.py: Demonstrate ICMP6 (v6) header decodes
# Copyright (C) 2015, Nevil Brownlee, U Auckland | WAND

from plt_testing import *

t = get_example_trace('icmp6-sample.pcap')

n = 0;  offset = 12

for pkt in t:
    icmp6 = pkt.icmp6
    if not icmp6:
        continue
    n += 1

    test_println("%5d: " % (n), get_tag()),
    print_icmp6(icmp6, offset, get_tag("n:"+str(n)))
    test_println('')

t.close
