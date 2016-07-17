#!/usr/bin/env python

# test-icmp6.py: count types of icmp6 packets
# Copyright (C) 2013, Nevil Brownlee, U Auckland | CAIDA | Wand

from plt_testing import *

from array import *

icmp_info = {}  # Empty dictionary

out_uri = 'pcapfile:icmp6-sample-out.pcap'
of = plt.output_trace(out_uri)
of.start_output()

n = 0

t = get_example_trace('icmp6-sample.pcap')
#  1: 28535  2: 20  3: 89094  4: 4413  128: 46447  129: 36085  134: 1382  135: 148720  136: 16188 
#t = get_rlt_example_file('icmp6.pcap')
#  1: 371  3: 32  4: 12  128: 37  129: 36  134: 5  135: 468  136: 39 

for pkt in t:
    n += 1
    icmp6 = pkt.icmp6
    if not icmp6:
        continue
    it = icmp6.type
    if it in icmp_info:
        icmp_info[it] += 1
    else:
        icmp_info[it] = 1
    if icmp_info[it] <= 4:
        of.write_packet(pkt)
t.close()
of.close_output()

test_println("%d packets examined\n" % (n), get_tag())

test_print("icmp6 types = ", get_tag())
for type in sorted(icmp_info):
    test_print("%d: %d " % (type, icmp_info[type]))
test_println('')
