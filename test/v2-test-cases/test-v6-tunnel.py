#!/usr/bin/env python

# Fri, 27 Jun 14 (NZST)
# test-ip6-tunnel.py:  Demonstrate IPv6 objects tunnelled in IPv4
# Copyright (C) 2015, Nevil Brownlee, U Auckland | WAND

from plt_testing import *

t = get_example_trace('tunnel.pcap')
    # tunnel.pcap has packets from a v6-in-v4 tunnell

n = 0
for pkt in t:
    n += 1  # Wireshark uses 1-org packet numbers
    ip = pkt.ip
    if not ip:
        test_println("%5d: non-IP packet" % (n), get_tag())
        continue

    d = ip.payload
    #print_data("<d>", 6, d, 120)
    ip6 = plt.ip6(d)

    test_println("%5d: " % (n), get_tag())
    print_ip6(ip6, 12, get_tag("n:"+str(n)))

    # tcp = pkt.tcp  # Fails - the IP part of pkt has IP6 as it's proto
    tcp = ip6.tcp    # We have to look at the decapsulated IPb
    if tcp:
        print_tcp(tcp, 12, get_tag("n:"+str(n)))

    #if n == 2:
    #    break

t.close()  # Don't do this inside the loop!
