#!/usr/bin/env python

# 1156, Thu  8 Jun 2017 (NZDT)
# test-pldns-tcp.py:  Demonstrate Ldns objects from tcp
# Copyright (C) 2017, Nevil Brownlee, U Auckland

import plt
import pldns
from plt_testing import *

t = plt.trace('pcapfile:dns_valid_response_tcp.pcap')
t.start()

n = 0;  margin = ' '*7
for pkt in t:
    n += 1  # Wireshark uses 1-org packet numbers
    ip = pkt.ip
    if not ip:
        continue  # Not IP
    if ip.frag_offset != 0:
        continue  # Non-first fragment

    tcp = pkt.tcp
    if not tcp:
        continue  # Not TCP
    if not (tcp.src_port == 53 or tcp.dst_port == 53):
        continue
    payload = tcp.payload
    if not payload:
        continue
    ldns_obj = pldns.ldns(payload)

    test_println("%5d: %s -> %s" % (n, tcp.src_prefix, tcp.dst_prefix), get_tag())
    if not ldns_obj.is_ok():
        test_println("%sCouldn't make ldns_obj, status = <%s>" % (
            margin, ldns_obj.errorstr(ldns_obj.status)), get_tag())
        continue

    rk = 'query'
    if ldns_obj.is_response:
        rk = 'response'
    test_println("%s%s, ident=%04x, opcode=%d (%s), rcode=%d (%s)" % (margin,
        rk, ldns_obj.ident, ldns_obj.opcode, pldns.opcodestr(ldns_obj.opcode),
        ldns_obj.rcode, pldns.rcodestr(ldns_obj.rcode)), get_tag())

    q_rr_list = ldns_obj.query_rr_list
    if not q_rr_list:
        test_println("%sQuery list empty" % margin, get_tag())
    else:
        test_println("%sQuery list (%d items)" % (margin, len(q_rr_list)), get_tag())
        for rr in q_rr_list:
            test_println("%s   %s\t%3d" % (margin, rr.owner, rr.type), get_tag())

    if ldns_obj.is_response:
        an_rr_list = ldns_obj.response_rr_list
        if not an_rr_list:
            test_println("%sResponse list empty" % margin, get_tag())
        else:
            test_println("%sResponse list (%d items)" % (margin, len(an_rr_list)), get_tag())
            for rr in an_rr_list:
                test_println("%s   %s\t%3d\t%s\t%s" % (margin,
                    rr.owner, rr.ttl, pldns.typestr(rr.type), rr.rdata), get_tag())

        au_rr_list = ldns_obj.auth_rr_list
        if not au_rr_list:
            test_println("%sAuthority list empty" % margin, get_tag())
        else:
            test_println("%sAuthority list (%d items)" % (margin, len(au_rr_list)), get_tag())
            for rr in au_rr_list:
                test_println("%s   %s\t%3d\t%s\t%s" % (margin,
                    rr.owner, rr.ttl, pldns.typestr(rr.type), rr.rdata), get_tag())

        ad_rr_list = ldns_obj.addit_rr_list
        if not ad_rr_list:
            test_println("%sAdditional list empty" % margin, get_tag())
        else:
            test_println("%sAdditional list (%d items)" % (margin, len(ad_rr_list)), get_tag())
            for rr in ad_rr_list:
                test_println("%s   %s\t%3d\t%s\t%s" % (margin,
                    rr.owner, rr.ttl, pldns.typestr(rr.type), rr.rdata), get_tag())
    test_println('', get_tag())  # Blank line

    #if n == 20:  # Packet 551 is a first fragment
    #    break

t.close()  # Don't do this inside the loop!

test_println("%d packets read" % n, get_tag())
