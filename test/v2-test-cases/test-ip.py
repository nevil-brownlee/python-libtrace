#!/usr/bin/env python

# Thu, 13 Mar 14 (PDT)
# ip.py:  Demonstrate IP objects
# Copyright (C) 2015, Nevil Brownlee, U Auckland | WAND

from plt_testing import *

try:
    t = get_example_trace('anon-v5.pcap')
except:
    test_println("Error in get_example_trace()", get_tag())
    # sys.exc_clear()  # Not really needed
test_println("- - -", get_tag())

t = get_example_trace('anon-v4.pcap')

n = 0
for pkt in t:
    n += 1  # Wireshark uses 1-org packet numbers
    ip = pkt.ip
    if not ip:
        continue

    print_ip(ip, 12, get_tag("n:"+str(n)))
    test_println('')
    if n == 20:
        break

test_println("%5d packets accepted" % (t.pkt_accepts()), get_tag())
test_println("%5d packets dropped" % (t.pkt_drops()), get_tag())

t.close()  # Don't do this inside the loop!

