#!/usr/bin/env python

# Thu, 13 Mar 14 (PDT)
# encap-pkt.py: Test Packet methods and ip.new 
# Copyright (C) 2015, Nevil Brownlee, U Auckland | WAND

from plt_testing import *

t = get_example_trace('anon-v4.pcap')
#t = get_rlt_example_file('icmp-sample.pcap')

def compare_objects(a, b, msg):
   if a.data != b.data:  # Compare bytearrays
       print_data("a =", 5, a.data)
       print_data("b =", 5, b.data)
       print ">>> %s <<<" % msg
       sys.exit()

n = nip = 0;  offset = 12
for pkt in t:
    n += 1
    ip = pkt.ip
    if not ip:
        continue
    print "%5d:" % (n),
    print_ip(ip, offset)
    l3ip = plt.ip(pkt.layer3.data);
    compare_objects(ip, l3ip, "ip : layer3")

    tcp = pkt.tcp;  udp = pkt.udp;  icmp = pkt.icmp
    print "      ",
    if tcp:
        print_tcp(tcp, offset)
        ntcp = plt.tcp(ip)
        compare_objects(tcp, ntcp, "tcp : new tcp")
    elif udp:
        print_udp(udp, offset)
        nudp = plt.udp(ip)
        compare_objects(udp, nudp, "udp : new udp")
    elif icmp:
        print_icmp(icmp, offset)
        nicmp = plt.icmp(ip)
        compare_objects(icmp, nicmp, "icmp : new icmp")
    else:
        margin = ' ' * offset
        print "Unknown: proto=%d" % (ip.proto)
    print

    nip += 1
    if nip >= 15:
       break 

t.close
