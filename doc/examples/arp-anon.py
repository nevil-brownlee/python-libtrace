#!/usr/bin/env python

# Thu, 13 Mar 14 (PDT)
# arp-anon.py:  Anonymise IPv4 addresses in ARP records
# Copyright (C) 2015, Nevil Brownlee, U Auckland | WAND

# python arp-anon.py  pcapfile:anon-v4.pcap  pcapfile:first-n.pcap  30

from plt_testing import *

#import sys  # argv, exit

in_fn = 'anon-v4.pcap'

#doc_ipv4 = IPprefix.from_s('192.168.0.0/24')  # IPv4 'documentation' prefix

test_ipv4 = ipp.from_s('17.34.51.68')  # test prefix
new_addr = test_ipv4.addr  # 4-byte bytearray
print "test_ipv4 = %s" % test_ipv4
print "new_addr = %02x %02x %02x %02x" % (
    new_addr[0], new_addr[1], new_addr[2], new_addr[3])

t = get_example_trace(in_fn)

ot = plt.output_trace('pcapfile:arp-changed.pcap')
ot.start_output()
print "files opened ..."

n = nip = 0;  nudp = 0
for pkt in t:
    n += 1

    l3 = pkt.layer3
    if l3.ethertype == 0x0806:  # ARP
        d = l3.data  # Decode the ARP packet
        hw_type = d[0]*256 + d[1]
        protocol_type = d[2]*256 + d[3]
        hln = d[4]  # Length of h/w address
        pln = d[5]  # Length of protocol address
        opcode = d[6]*256 + d[7]
        print "hrd=%d, pro=%04x, hln=%d, pln=%d, opcode=%04x" % (
            hw_type, protocol_type, hln, pln, opcode)

        sax = 8+hln;  tax = sax+pln+hln  # Change sender and
        print "sax=%d, tax=%d" % (sax, tax)

        # CAUTION: python will replace a slice by a longer on,
        #   thus adding elements into a (byte)array.
        #   Here we're careful to replace 4 byte with another 4!
        d[sax:sax+pln] = new_addr     # target addresses in d
        d[tax:tax+pln] = new_addr

        l3.data = d  # Write changed addresses into pkt
        # pkt.layer3.data = d  # This also works

    ot.write_packet(pkt)
 
    if n == 5:
        break

ot.close_output;  t.close
