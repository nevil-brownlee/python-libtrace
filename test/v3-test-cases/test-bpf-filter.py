#!/usr/bin/env python

# Thu, 13 Mar 14 (PDT)
# bpf-filter.rb: Create a packet filter,
#                use it to print udp records from a trace
# Copyright (C) 2015, Nevil Brownlee, U Auckland | WAND

from plt_testing import *

t = get_example_trace('anon-v4.pcap')

filter = plt.filter('udp port 53')  # Only want DNS packets

t.conf_filter(filter)
t.conf_snaplen(500)
#t.conf_promisc(True)
   # Remember: on a live interface, must sudo to capture
   #           on a trace file, can't set promicuous

nfp = 0;  offset = 12
for pkt in t:
    nfp += 1

    udp = pkt.udp
    test_println("%4d:" % (nfp), get_tag())
    print_udp(pkt.udp, offset, get_tag("nfp:"+str(nfp)))
    test_println('')

    if nfp == 4:
        break

test_println("%d filtered packets" % nfp, get_tag())
