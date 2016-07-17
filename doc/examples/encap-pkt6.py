#!/usr/bin/env python

# Thu, 13 Mar 14 (PDT)
# encap-pkt6.py: Test Packet methods and ip6.new 
# Copyright (C) 2015, Nevil Brownlee, U Auckland | WAND

from plt_testing import *

t = get_example_trace('anon-v6.pcap')

def compare_objects(a, b, msg):
   if a.data != b.data:  # Compare bytearrays
       print_data("a =", 5, a.data)
       sys.exit()
       print_data("b =", 5, b.data)
       print ">>> %s <<<"
       sys.exit()

n = nip6 = 0;  offset = 12
for pkt in t:
    n += 1
    ip6 = pkt.ip6
    if not ip6:
        continue
    print "%5d:" % (n),
    nip6 += 1
    print_ip6(ip6, offset)
    l3ip6 = plt.ip6(pkt.layer3.data);
    compare_objects(ip6, l3ip6, "ip : layer3")

    tcp = pkt.tcp;  udp = pkt.udp;  icmp6 = pkt.icmp6
    if tcp:
        continue
        print_tcp(tcp, offset)
        ntcp = plt.tcp(ip6)
        compare_objects(tcp, ntcp, "tcp : new tcp")
    elif udp:
        print_udp(udp, offset)
        nudp = plt.udp(ip6)
        print ">>>tcp={0}, ntcp={1}" . format(udp, nudp)
        compare_objects(udp, nudp, "udp : new udp")
    elif icmp6:
        print_icmp6(icmp6, offset)
        nicmp6 = plt.icmp6(ip6)
        compare_objects(icmp6, nicmp6, "icmp6 : new icmp6")
    else:
        margin = ' ' * offset
        print "Unknown: proto=%d" % (ip6.proto)

    if nip6 == 15:
        break 

t.close
