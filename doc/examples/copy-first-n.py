#!/usr/bin/env python

# Thu, 13 Mar 14 (PDT)
# copy-first-n.rb: Copies first n records from one trace to another
# Copyright (C) 2015, Nevil Brownlee, U Auckland | WAND

# python copy-first-n.py  pcapfile:anon-v4.pcap  pcapfile:first-n.pcap  30

import plt  # Also imports IPprefix and datetime

import sys     #  argv, exit

in_uri = sys.argv[1]  # Program name is argv[0]
out_uri = sys.argv[2]
n_records = sys.argv[3]
if not n_records or int(n_records) <= 0:
    print "Number of records to copy not specified <<<"
    exit()
else:
    n_records = int(n_records)
    print "copying first %d records from %s to %s ..." % (
        n_records, in_uri, out_uri)

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

ot.close_output();  t.close()
