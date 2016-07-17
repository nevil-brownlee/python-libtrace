#!/usr/bin/env python

# Thu, 13 Mar 14 (PDT)
# ip6.py:  Demonstrate IPv6 objects
# Copyright (C) 2015, Nevil Brownlee, U Auckland | WAND

#import ipp
import plt
import natkit
from plt_testing import *
import sys

UAv4 = ipp.from_s("130.216.0.0/16")
UAv6 = ipp.from_s("2001:df0::/47")
linklocal = ipp.from_s("fe80::/10")
multicast = ipp.from_s("ff00::/8")

fh = natkit.FlowHome(UAv4, UAv6)  # List of 'home' prefixes'
#  hf = fh(pkt) returns:
#    hf.src_in_home
#    hf.dst_in_home
#
#    hf.home_key = if src in home or dst in home 
#                   flow key with home address as dest
#                  else  None
#    hf.inward   = True if pkt dest was in home
#                    (outward home_key has addresses and ports swapped)

def print_flow(n, ipf, tag=''):
    test_println("%5d: %d %3d  %5d %5d  %s  %s" % (n,  # v6
        ipf.version, ipf.proto, ipf.src_port, ipf.dst_port,
        ipf.src_prefix, ipf.dst_prefix), tag+get_tag())

    #key = ipf.fwd_key
    #for b in key:
    #    print " %02x" % ord(b),
    #print

    test_println("          src_home=%s, dst_home=%s, is_inward=%s" % (
        ipf.src_in_home, ipf.dst_in_home, ipf.is_inward), tag+get_tag())
            

def test_uri(uri, tag=''):
    t = plt.trace(uri)
    t.start()

    nip6 = nip = n = 0
    for pkt in t:
        n += 1

        if not (pkt.ip or pkt.ip6):
            continue

        try:
            ipf = fh.flow(pkt)
        except:
            test_println("%4d: probably not an IP packet" % n, tag+get_tag("n:"+str(n)))
            continue

        if not ipf.is_inward:
            print_flow(n, ipf, tag+get_tag("n:"+str(n)))
        else:
            if pkt.ip:
                nip += 1
                #if nip <= 4:
                print_flow(n, ipf, tag+get_tag("n:"+str(n)))
            elif pkt.ip6:
                nip6 += 1
                #if nip6 <= 4:
                print_flow(n, ipf, tag+get_tag("n:"+str(n)))

            fwd = ipf.fwd_key
            test_print("fwd =", tag+get_tag("n:"+str(n)))
            for b in fwd:
                test_print(" %02x" % b)

            test_println('')
            hk = ipf.home_key
            test_print('', tag+get_tag("n:"+str(n)))
            test_print("hom =")
            for b in hk:
                test_print(" %02x" % b)
            test_println('')

        #if n == 480:
        #    break

    t.close()

test_uri("pcapfile:home-test.pcap", get_tag())
