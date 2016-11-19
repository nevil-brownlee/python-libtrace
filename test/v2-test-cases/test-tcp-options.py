# 1008, Saun 13 Nov 2016 (KST)
#
# test-tcp-options.py: Test tcp options handling in plt
#
# Copyright (C) 2016, Nevil Brownlee, U Auckland | WAND

from plt_testing import *

tcp_fn = "anon-v4.pcap"

def test_option(n):
    xn = tcp.option(n)
    if isinstance(xn, bool):
        test_println("  opt %d: > %s <" % (n, xn), get_tag())
    else:
        test_print(("  opt %d: >" % n,), tag='')
        for c in xn:
            test_print(("%02x" % c,), tag='')
        test_println("<", get_tag())

t = plt.trace("pcapfile:"+tcp_fn)
t.start()

n = 0
for pkt in t:
    n += 1
    tcp = pkt.tcp
    if not tcp:
        continue
    if tcp.doff == 5:  # No TCP options
        continue

    test_println("pkt %d ---" % n, get_tag())
    xod = tcp.options_data
    for c in xod:
        test_print(("%02x" % c,), tag='')
    test_println("(%d)" % len(xod), get_tag())

    ol = tcp.options_ba
    for opt in ol:
        test_option(opt)

    if n == 40:
        break

t.close
