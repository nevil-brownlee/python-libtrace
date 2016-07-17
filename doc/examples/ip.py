#!/usr/bin/env python

# Thu, 13 Mar 14 (PDT)
# ip.py:  Demonstrate IP objects
# Copyright (C) 2015, Nevil Brownlee, U Auckland | WAND

from plt_testing import *

try:
    t = get_example_trace('anon-v5.pcap')
except:
    print "Error in get_example_trace()"
    # sys.exc_clear()  # Not really needed
print "- - -"

t = get_example_trace('anon-v4.pcap')

n = 0
for pkt in t:
    n += 1  # Wireshark uses 1-org packet numbers
    ip = pkt.ip
    if not ip:
        continue

    print_ip(ip, 12)
    print
    if n == 20:
        break

print "%5d packets accepted" % (t.pkt_accepts())
print "%5d packets dropped" % (t.pkt_drops())

t.close()  # Don't do this inside the loop!

