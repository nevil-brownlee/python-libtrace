# 1008, Sun 13 Nov 2016 (KST)
#
# tcp-options.py: Test tcp options handling in plt
#
# Copyright (C) 2016, Nevil Brownlee, U Auckland | WAND

import plt

tcp_fn = "anon-v4.pcap"

def test_option(n):
    xn = tcp.option(n)
    if isinstance(xn, bool):
        print("  opt %d: > %s <" % (n, xn))
    else:
        oline = "  opt %d: >" % n
        for c in xn:
            oline +=" %02x" % c
        print(oline + " <")

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

    print("pkt %d ---" % n)
    xod = tcp.options_data
    oline = " "
    for c in xod:
        oline += " %02x" % c
    print(oline + "  (%d)" % len(xod))

    ol = tcp.options_ba
    for opt in ol:
        test_option(opt)

    if n == 40:
        break

t.close
