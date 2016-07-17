#!/usr/bin/env python

# Thu, 13 Mar 14 (PDT)
# ip6.py:  Demonstrate IPv6 objects
# Copyright (C) 2015, Nevil Brownlee, U Auckland | WAND

import plt
import natkit as nk
from plt_testing import *

#ba = bytearray(b"\x10\x02\x20\x04\x30\x05\x40\x06")
ba = bytearray.fromhex(u"1002 2004 3005 4006")
test_print('', get_tag())
for b in ba: test_print("%02x " % b)
test_println('')

test_print('', get_tag())
test_print("short[2] = %04x " % nk.ba_get_short(ba,2))
test_print("short[4] = %04x " % nk.ba_get_short(ba,4))
test_print("long[2]  = %08x " % nk.ba_get_long(ba,2))
test_println("long[5]  = %s\n" % nk.ba_get_long(ba,5))

a=5;  b=6
test_println("a=%x, b=%x,  a>b = %s" % (a, b, nk.seq_gt(a,b)), get_tag())
test_println("a=%x, b=%x, a>=b = %s" % (a, b, nk.seq_ge(a,b)), get_tag())
test_println("a=%x, b=%x, a<b  = %s\n" % (a, b, nk.seq_lt(a,b)), get_tag())

a = 0xffff0000;  b = 0xfffeffff  # b < a
test_println("a=%x, b=%x,  a+b= %x" % (a, b, nk.seq_add(a,b)), get_tag())
test_println("a=%x, b=%x,  a-b= %x\n" % (a, b, nk.seq_sub(a,b)), get_tag())

test_println("a=%x, b=%x,  a>b = %s" % (a, b, nk.seq_gt(a,b)), get_tag())
test_println("a=%x, b=%x, a>=b = %s" % (a, b, nk.seq_ge(a,b)), get_tag())
test_println("a=%x, b=%x, a<b  = %s\n" % (a, b, nk.seq_lt(a,b)), get_tag())

b = 0xffff0001  # b > a
test_println("a=%x, b=%x,  a>b = %s" % (a, b, nk.seq_gt(a,b)), get_tag())
test_println("a=%x, b=%x, a>=b = %s" % (a, b, nk.seq_ge(a,b)), get_tag())
test_println("a=%x, b=%x, a<b  = %s\n" % (a,b, nk.seq_lt(a,b)), get_tag())

b = a
test_println("a=%x, b=%x,  a>b = %s" % (a, b, nk.seq_gt(a,b)), get_tag())
test_println("a=%x, b=%x, a>=b = %s" % (a, b, nk.seq_ge(a,b)), get_tag())
test_println("a=%x, b=%x, a<b  = %s\n" % (a, b, nk.seq_lt(a,b)), get_tag())
