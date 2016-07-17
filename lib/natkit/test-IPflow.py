#!/usr/bin/env python

# Thu, 13 Mar 14 (PDT)
# ip6.py:  Demonstrate IPv6 objects
# Copyright (C) 2014, Nevil Brownlee, U Auckland | WAND

import plt
import natkit

def test_uri(uri):
    t = plt.trace(uri)
    t.start()

    nip = n = 0
    for pkt in t:
        n += 1
        print "n = %d" % n
        try:
            ipf = natkit.IPflow(pkt)
        except:
            print "probably not an IP packet"
            continue

        nip += 1

        print "%5d: %d %3d  %5d %5d  %s  %s" % (n,  # v6
           ipf.version, ipf.proto, ipf.src_port, ipf.dst_port,
           ipf.src_prefix, ipf.dst_prefix)

        fwd = ipf.fwd_key
        print "fwd =",
        for b in fwd:
            print " %02x" % ord(b),

        rev = ipf.rev_key
        print "\nrev =",
        for b in rev:
            print " %02x" % ord(b),
        print

        if nip == 4:
            break

    t.close()

pcap_dir = '../../doc/examples'
test_uri('pcapfile:'+pcap_dir+'/anon-v4.pcap')
test_uri('pcapfile:'+pcap_dir+'/anon-v6.pcap')
