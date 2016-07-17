#!/usr/bin/env python

# icmp.py: Demonstrate UDP header decodes
# Copyright (C) 2015, Nevil Brownlee, U Auckland | WAND

from plt_testing import *

from array import *

#icmp_types = {}  # Empty Dictionary
icmp_array = array('i', [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])

out_uri = 'pcapfile:icmp-full.pcap'
of = plt.OutputTrace(out_uri)
of.start_output()

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

print "%d packets examined\n" % (n)

print icmp_array

for j in range(0, 12):
   print "%2d: %6d" % (j, icmp_array[j])
