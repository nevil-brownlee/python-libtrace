
import sys

def pba(ba):
    sys.stdout.write("<")
    for n,x in enumerate(ba):
        if n != 0:
            sys.stdout.write(" ")
        print "%02x" % x,
    sys.stdout.write(">\n")

ba = bytearray( [1, 2, 3, 4])
pba(ba)

ba2 = bytearray([17, 34])

ba[0:2] = ba2;  pba(ba)
ba[1:3] = ba2;  pba(ba)
ba[2:4] = ba2;  pba(ba)
