#!/usr/bin/env python

# Thu, 13 Mar 14 (PDT)
# copy-first-n.rb: Copies first n records from one trace to another
# Copyright (C) 2015, Nevil Brownlee, U Auckland | WAND

# python copy-first-n.py  pcapfile:anon-v4.pcap  pcapfile:first-n.pcap  30

import plt  # Also imports IPprefix and datetime

import sys     #  argv, exit
from plt_testing import *

in_uri = 'pcapfile:icmp-sample.pcap'
out_uri = 'pcapfile:icmp-sample-out.pcap'
n_records = 10
test_println("copying first %d records from %s to %s ..." % (
        n_records, in_uri, out_uri), get_tag())

t = plt.trace(in_uri)
t.start()

ot = plt.output_trace(out_uri)
ot.start_output()

n = 0
for pkt in t:
    n += 1

    ot.write_packet(pkt)

    if n == n_records:
        break

if n != n_records:
    test_println("error copying records. only %d out of %d were copied." % (n, n_records), get_tag())
else:
    test_println("%d records were copied successfully." % (n), get_tag())

ot.close_output();  t.close()

