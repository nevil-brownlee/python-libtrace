
import sys
from plt_testing import *

def pba(ba, tag=''):
    sys.stdout.write(tag+get_tag()+" <")
    for n,x in enumerate(ba):
        if n != 0:
            sys.stdout.write(" ")
        test_print("%02x" % x)
    sys.stdout.write(">\n")

ba = bytearray( [1, 2, 3, 4])
pba(ba)

ba2 = bytearray([17, 34])

ba[0:2] = ba2;  pba(ba, get_tag())
ba[1:3] = ba2;  pba(ba, get_tag())
ba[2:4] = ba2;  pba(ba, get_tag())
