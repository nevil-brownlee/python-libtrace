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
print "plt version = {0}".format(v)

#d = plt.Data(3)
#print "d={0}\n".format(d)

t = get_example_trace('anon-v4.pcap')

p = plt.packet()
np = 0
while np != 12:
    t.read_packet(p)
    print "np=%d, %s" % (np, p)
    np += 1
    ip = p.ip
    if ip:
        print "%3d, ip = <%s>" % (np, ip)
        print "   wlen=%d, caplen=%d, src=%s, dst=%s" % (
            p.wire_len, p.capture_len, ip.src_prefix, ip.dst_prefix)

n = 0
for pkt in t:
    n += 1  # Wireshark uses 1-org packet numbers
    print "n=%d" % (n)
    linktype = pkt.linktype
    ethertype = pkt.ethertype
    print "n=%d, linktype=%d, ethertype=%04x " % (n, linktype, ethertype)
    if n == 5:
        break
    ip = pkt.ip
    if not ip:
        continue
 
    pt = pkt.time
    print "time = >{0}<".format(pt)
    # pkt.time = 20.5
    # print "seconds=%f, ts_sec=%u, erf_time=%llu" % (pkt.seconds, pkt.ts_sec, pkt.erf_time)
    print "seconds={0}, ts_sec={1}, erf_time={2}".format(pkt.seconds, pkt.ts_sec, pkt.erf_time)

    wlen = pkt.wire_len;  clen = pkt.capture_len
    print "n=%d, wlen=%d, clen=%d" % (n, wlen, clen)
    print "***** ip={0}\n" . format(ip)
    print "   ver=%d, %s -> %s, proto=%d, tclass=%d, ttl=%d, hlen=%d, plen=%d" % (
        ip.version, ip.src_prefix, ip.dst_prefix,
        ip.proto, ip.traffic_class, ip.hop_limit, ip.hdr_len, ip.pkt_len)

#    io = 55
#    print "io = {0}".format(io)

    ip.traffic_class = 55;
    ip.hop_limit = (123);
    print "== ver=%d, %s -> %s, proto=%d, tclass=%d, ttl=%d, hlen=%d, plen=%d" % (
        ip.version, ip.src_prefix, ip.dst_prefix,
        ip.proto, ip.traffic_class, ip.hop_limit, ip.hdr_len, ip.pkt_len)

    ethertype = ip.ethertype
    linktype = ip.linktype
    print "   from ip: linktype=%d, ethertype=%04x" % (linktype, ethertype)

    # print "ip.info() = [%s]" % (ip.info())

    print "%s -> %s " % (ip.src_prefix, ip.dst_prefix)
    ip.src_prefix = ipp.from_s("1.2.3.4")
    ip.dst_prefix = ipp.from_s("5.6.7.8")
    print "now %s => %s " % (ip.src_prefix, ip.dst_prefix)
#    ip.version = 5 # Read-only!

t.close()  # Don't do this inside the loop!

print "%d packets in trace\n" % (n)





