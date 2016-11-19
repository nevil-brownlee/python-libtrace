# 1008, Saun 13 Nov 2016 (KST)
#
# test-tcp-options.py: Test tcp options handling in plt
#
# Copyright (C) 2016, Nevil Brownlee, U Auckland | WAND

import plt

tcp_fn = "anon-v4.pcap"

def test_option(n):
    xn = tcp.option(n)
    if isinstance(xn, bool):
        print "  opt %d: > %s <" % (n, xn)
    else:
        print "  opt %d: >" % n,
        for c in xn:
            print "%02x" % c,
        print"<"

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
    options = tcp.data[20:tcp.doff*4]

    print "pkt %d ---" % n
    xod = tcp.options_data
    for c in xod:
        print "%02x" % c,
    print "(%d)" % len(xod)

    ol = tcp.options_ba
    for opt in ol:
        test_option(opt)

    if n == 40:
        break

t.close
