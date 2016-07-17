#!/usr/bin/env python

#Nevil's parta.py - parta in Python

import getopt
import sys
import plt
from plt_testing import *

t = get_example_trace('1000packets.pcap.gz')
#t = get_example_trace('vlan.pcap.gz')
t.start()

tcp_n = tcp_syn = tcp_synack = udp_n = icmp_n = ipv6_n = 0
np = nb = b_in = b_out = 0
last_ts = start_ts = None

for pkt in t:
    np += 1
    last_ts = pkt.seconds
    if not start_ts:
        test_println("pkt.seconds=%f, ts_sec=%d, pkt_time=%s" % (
           last_ts, pkt.ts_sec, pkt.time), get_tag("np:"+str(np)))
        start_ts = last_ts
    nb += pkt.capture_len

    p_dir = pkt.direction
    #print "%4d: p_dir=%d" % (np, p_dir)
    wb = pkt.wire_len
    if p_dir == plt.TRACE_DIR_INCOMING:
        b_in += wb
    elif p_dir == plt.TRACE_DIR_OUTGOING:
        b_out += wb

    ip = pkt.ip
    if ip:
        tcp = ip.tcp
        if tcp:
            tcp_n += 1
            flags = tcp.flags
            if flags == 0x02:
                tcp_syn += 1
            elif flags == 0x12:
                tcp_synack += 1
        elif ip.udp:
            udp_n += 1
        elif ip.icmp:
            icmp_n += 1
    else:
        test_println("**", get_tag("np:"+str(np)))
        if pkt.ip6:
            ipv6_n += 1

trace_s = pkt.seconds - start_ts
#print "b_in=%d, b_out=%d, start=%f, last=%f, trace_s=%f" % (
#    b_in, b_out, start_ts, last_ts, trace_s)

test_println("Packet count: %d" % np, get_tag())
test_println("Captured bytes: %d" % nb, get_tag())

in_rate = b_in*8/(trace_s*1000000.0)
out_rate = b_out*8/(trace_s*1000000.0)
test_println("Bitrate inbound: %.2f Mbps" % in_rate, get_tag())
test_println("Bitrate outbound: %.2f Mbps\n" % out_rate, get_tag())

test_println("TCP packets: %d" % tcp_n, get_tag())
test_println("TCP SYN count: %d" % tcp_syn, get_tag())
test_println("TCP SYN ACK count: %d" % tcp_synack, get_tag())
test_println("UDP packets: %d" % udp_n, get_tag())
test_println("ICMP packets: %d" % icmp_n, get_tag())
test_println("IPv6 packets: %d" % ipv6_n, get_tag())

