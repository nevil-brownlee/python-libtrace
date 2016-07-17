#!/usr/bin/env python

# Thu, 13 Mar 14 (PDT)
# ip6.py:  Demonstrate IPv6 objects
# Copyright (C) 2014, Nevil Brownlee, U Auckland | WAND

import plt
import natkit as nk

#ba = bytearray(b"\x10\x02\x20\x04\x30\x05\x40\x06")
ba = bytearray.fromhex(u"1002 2004 3005 4006")
for b in ba: print "%02x " % b,
print

print "short[2] = %04x" % nk.ba_get_short(ba,2),
print "short[4] = %04x" % nk.ba_get_short(ba,4),
print "long[2]  = %08x" % nk.ba_get_long(ba,2),
print "long[5]  = %s\n" % nk.ba_get_long(ba,5)

a=5;  b=6
print "a=%x, b=%x,  a>b = %s" % (a, b, nk.u32_gt(a,b))
print "a=%x, b=%x, a>=b = %s" % (a, b, nk.u32_ge(a,b))
print "a=%x, b=%x, a<b  = %s\n" % (a, b, nk.u32_lt(a,b))

a = 0xffff0000;  b = 0xfffeffff  # b < a
print "a=%x, b=%x,  a+b= %x" % (a, b, nk.u32_add(a,b))
print "a=%x, b=%x,  a-b= %x\n" % (a, b, nk.u32_sub(a,b))

print "a=%x, b=%x,  a>b = %s" % (a, b, nk.u32_gt(a,b))
print "a=%x, b=%x, a>=b = %s" % (a, b, nk.u32_ge(a,b))
print "a=%x, b=%x, a<b  = %s\n" % (a, b, nk.u32_lt(a,b))

b = 0xffff0001  # b > a
print "a=%x, b=%x,  a>b = %s" % (a, b, nk.u32_gt(a,b))
print "a=%x, b=%x, a>=b = %s" % (a, b, nk.u32_ge(a,b))
print "a=%x, b=%x, a<b  = %s\n" % (a,b, nk.u32_lt(a,b))

b = a
print "a=%x, b=%x,  a>b = %s" % (a, b, nk.u32_gt(a,b))
print "a=%x, b=%x, a>=b = %s" % (a, b, nk.u32_ge(a,b))
print "a=%x, b=%x, a<b  = %s\n" % (a, b, nk.u32_lt(a,b))
