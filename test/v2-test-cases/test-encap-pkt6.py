#!/usr/bin/env python

# Thu, 13 Mar 14 (PDT)
# encap-pkt6.py: Test Packet methods and ip6.new 
# Copyright (C) 2015, Nevil Brownlee, U Auckland | WAND

from plt_testing import *

t = get_example_trace('anon-v6.pcap')

def compare_objects(a, b, msg, tag=''):
   if a.data != b.data:  # Compare bytearrays
       print_data("a =", 5, a.data, tag)
       sys.exit()
       print_data("b =", 5, b.data, tag)
       test_println(">>> %s <<<", tag)
       sys.exit()

n = nip6 = 0;  offset = 12
for pkt in t:
    n += 1
    ip6 = pkt.ip6
    if not ip6:
        continue
    test_println("%5d:" % (n), get_tag())
    nip6 += 1
    print_ip6(ip6, offset, get_tag("n:"+str(n)))
    l3ip6 = plt.ip6(pkt.layer3.data);
    compare_objects(ip6, l3ip6, "ip : layer3", get_tag("n:"+str(n)))

    tcp = pkt.tcp;  udp = pkt.udp;  icmp6 = pkt.icmp6
    if tcp:
        continue
        print_tcp(tcp, offset, get_tag("n:"+str(n)))
        ntcp = plt.tcp(ip6)
        compare_objects(tcp, ntcp, "tcp : new tcp", get_tag("n:"+str(n)))
    elif udp:
        print_udp(udp, offset, get_tag("n:"+str(n)))
        nudp = plt.udp(ip6)
        test_println(">>>tcp={0}, ntcp={1}" . format(udp, nudp), get_tag("n:"+str(n)))
        compare_objects(udp, nudp, "udp : new udp", get_tag("n:"+str(n)))
    elif icmp6:
        print_icmp6(icmp6, offset, get_tag("n:"+str(n)))
        nicmp6 = plt.icmp6(ip6)
        compare_objects(icmp6, nicmp6, "icmp6 : new icmp6", get_tag("n:"+str(n)))
    else:
        margin = ' ' * offset
        test_println("Unknown: proto=%d" % (ip6.proto), get_tag("n:"+str(n)))

    if nip6 == 15:
        break 

t.close
