# 1123, Tue 30 Jan 2018 (NZDT)
#
# test-sctp.py: Test SCTP handling in plt
#
# Copyright (C) 2018, Nevil Brownlee, U Auckland | WAND

from plt_testing import *

import plt

tcp_fn = "sctp-demo.pcap"  # Data file name

t = plt.trace("pcapfile:"+tcp_fn)
t.start()        # Start t

n = 0
for pkt in t:  # Get next packet
    n += 1     # Count it
    sctp = pkt.sctp
    if not sctp:
        continue
    s = "%4d: src_port %u, dst_port %d, vf tag %08x, checksum %08x" % (
        n, sctp.src_port, sctp.dst_port, sctp.verification_tag, sctp.checksum)
    test_println(s, get_tag())

    cho = sctp.chunks
    for cx,ch in enumerate(cho):  ###sctp.chunks):
        s = "%4d    chunk %d:  type %d, flags %02x length %d bytes OK %s " % (
            n, cx, ch.type, ch.flags, ch.length, ch.is_ok)
        test_println(s, get_tag())
        s = "  "*9 + "bytes:"
        for x,c in enumerate(ch.bytes):
            if x == 16:
                break
            s += " %02x" % c
        test_println(s, get_tag())
    test_println("", get_tag())
    #if n == 5:
    #    break
    
t.close()

test_println("%d packets examined\n" % n, get_tag())
