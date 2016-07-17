#!/usr/bin/env python

# Thu, 13 Mar 14 (PDT)
# plt-test.py:  Test packet-level attributes
# Copyright (C) 2015, Nevil Brownlee, U Auckland | WAND

import socket
import sys

from plt_testing import *

#dt = datetime.datetime.utcnow()  # class
#print "***** dt = {0}".format(dt)

#t = plt.ipp_obj(4, "1234")
#print "t = {0}\n".format(t)

v = plt.version()
test_println("plt version = {0}".format(v), get_tag())

#d = plt.Data(3)
#print "d={0}\n".format(d)

t = get_example_trace('anon-v4.pcap')

p = plt.packet()
np = 0
while np != 12:
    t.read_packet(p)
#  print "np=%d, %s" % (np, p)
    test_println("np=%d" % (np), get_tag())
    np += 1
    ip = p.ip
    if ip:
#        print "%3d, ip = <%s>" % (np, ip)
        test_println("%3d" % (np), get_tag())
        test_println("   wlen=%d, caplen=%d, src=%s, dst=%s" % (
            p.wire_len, p.capture_len, ip.src_prefix, ip.dst_prefix), get_tag("np:"+str(np)))

n = 0
for pkt in t:
    n += 1  # Wireshark uses 1-org packet numbers
    test_println("n=%d" % (n), get_tag())
    linktype = pkt.linktype
    ethertype = pkt.ethertype
    test_println("n=%d, linktype=%d, ethertype=%04x " % (n, linktype, ethertype), get_tag("n:"+str(n)))
    if n == 5:
        break
    ip = pkt.ip
    if not ip:
        continue
 
    pt = pkt.time
    test_println("time = >{0}<".format(pt), get_tag("n:"+str(n)))
    # pkt.time = 20.5
    # print "seconds=%f, ts_sec=%u, erf_time=%llu" % (pkt.seconds, pkt.ts_sec, pkt.erf_time)
    test_println("seconds={0}, ts_sec={1}, erf_time={2}".format(pkt.seconds, pkt.ts_sec, pkt.erf_time), get_tag("n:"+str(n)))

    wlen = pkt.wire_len;  clen = pkt.capture_len
    test_println("n=%d, wlen=%d, clen=%d" % (n, wlen, clen), get_tag("n:"+str(n)))
#    print "***** ip={0}\n" . format(ip)
    test_println("   ver=%d, %s -> %s, proto=%d, tclass=%d, ttl=%d, hlen=%d, plen=%d" % (
        ip.version, ip.src_prefix, ip.dst_prefix,
        ip.proto, ip.traffic_class, ip.hop_limit, ip.hdr_len, ip.pkt_len), get_tag("n:"+str(n)))

#    io = 55
#    print "io = {0}".format(io)

    ip.traffic_class = 55;
    ip.hop_limit = (123);
    test_println("== ver=%d, %s -> %s, proto=%d, tclass=%d, ttl=%d, hlen=%d, plen=%d" % (
        ip.version, ip.src_prefix, ip.dst_prefix,
        ip.proto, ip.traffic_class, ip.hop_limit, ip.hdr_len, ip.pkt_len), get_tag("n:"+str(n)))

    ethertype = ip.ethertype
    linktype = ip.linktype
    test_println("   from ip: linktype=%d, ethertype=%04x" % (linktype, ethertype), get_tag("n:"+str(n)))

    # print "ip.info() = [%s]" % (ip.info())

    test_println("%s -> %s " % (ip.src_prefix, ip.dst_prefix), get_tag("n:"+str(n)))
    ip.src_prefix = ipp.from_s("1.2.3.4")
    ip.dst_prefix = ipp.from_s("5.6.7.8")
    test_println("now %s => %s " % (ip.src_prefix, ip.dst_prefix), get_tag("n:"+str(n)))
#    ip.version = 5 # Read-only!

t.close()  # Don't do this inside the loop!

test_println("%d packets in trace\n" % (n), get_tag())





