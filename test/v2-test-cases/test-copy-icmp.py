#!/usr/bin/env python

# icmp.py: Demonstrate UDP header decodes
# Copyright (C) 2015, Nevil Brownlee, U Auckland | WAND

from plt_testing import *

from array import *

#icmp_types = {}  # Empty Dictionary
icmp_array = array('i', [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])

out_uri = 'pcapfile:icmp-sample-out.pcap'
of = plt.output_trace(out_uri)
of.start_output()

t = get_example_trace('icmp-sample.pcap')
n = 0

for pkt in t:
    n += 1

    icmp = pkt.icmp
    if not icmp:
        continue

    it = icmp.type
    icmp_array[it] += 1   

    if icmp_array[it] <= 4:
        of.write_packet(pkt)

t.close();  of.close_output()

test_println("%d packets examined\n" % (n), get_tag())

test_println(str(icmp_array), get_tag())

for j in range(0, 12):
   test_println("%2d: %6d" % (j, icmp_array[j]), get_tag())
