#!/usr/bin/env python

# Thu, 13 Mar 14 (PDT)
# encap-pkt.py: Test Packet methods and ip.new 
# Copyright (C) 2015, Nevil Brownlee, U Auckland | WAND

from plt_testing import *

t = get_example_trace('anon-v4.pcap')
#t = get_rlt_example_file('icmp-sample.pcap')

def compare_objects(a, b, msg, tag=''):
   if a.data != b.data:  # Compare bytearrays
       print_data("a =", 5, a.data, tag+get_tag())
       print_data("b =", 5, b.data, tag+get_tag())
       test_println(">>> %s <<<" % msg, tag+get_tag())
       sys.exit()

n = nip = 0;  offset = 12
for pkt in t:
    n += 1
    ip = pkt.ip
    if not ip:
        continue
    test_println("%5d:" % (n), get_tag())
    print_ip(ip, offset, get_tag("n:"+str(n)))
    l3ip = plt.ip(pkt.layer3.data);
    compare_objects(ip, l3ip, "ip : layer3", get_tag("n:"+str(n)))
    tcp = pkt.tcp;  udp = pkt.udp;  icmp = pkt.icmp
#    print "      ",
    if tcp:
        print_tcp(tcp, offset, get_tag("n:"+str(n)))
        ntcp = plt.tcp(ip)
        compare_objects(tcp, ntcp, "tcp : new tcp", get_tag("n:"+str(n)))
    elif udp:
        print_udp(udp, offset, get_tag("n:"+str(n)))
        nudp = plt.udp(ip)
        compare_objects(udp, nudp, "udp : new udp", get_tag("n:"+str(n)))
    elif icmp:
        print_icmp(icmp, offset, get_tag("n:"+str(n)))
        nicmp = plt.icmp(ip)
        compare_objects(icmp, nicmp, "icmp : new icmp", get_tag("n:"+str(n)))
    else:
        margin = ' ' * offset
        test_println("Unknown: proto=%d" % (ip.proto), get_tag("n:"+str(n)))
    test_println('')

    nip += 1
    if nip >= 15:
       break 

t.close
