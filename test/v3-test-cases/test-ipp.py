
import ipp
import sys  # except handlers
from plt_testing import *
import binascii

bs = b'\x01\x02\x03\x04\x05\x06\x07\x08,0x09\x00\x81\x82'
ipp3 = ipp.IPprefix(6, bytearray(bs), 48)
test_println('3: version={0}, addr={1}, length={2}'.format(ipp3.version, binascii.hexlify(ipp3.addr), ipp3.length), get_tag())

ipp2 = ipp.IPprefix(4, bytearray([192, 168]))
test_println('2: version={0}, addr={1}'.format(ipp2.version, binascii.hexlify(ipp2.addr)), get_tag())

ipp1 = ipp.IPprefix(4, bytearray())
test_println(str('1: version={0}\n'.format(ipp1.version)), get_tag())

test_println(str("ipp3 = %s" % ipp3), get_tag())
test_println(str("ipp2 = %s" % ipp2), get_tag())
test_println(str("ipp1 = %s" % str(ipp1)), get_tag())

test_println(str("addrs: ipp3 = %s   ipp2 = %s" % (binascii.hexlify(ipp3.addr), binascii.hexlify(ipp2.addr))), get_tag())

ipp3.length = 7
test_println(str('len=7: version={0}, addr={1}, length={2}\n'.format(ipp3.version, binascii.hexlify(ipp3.addr), ipp3.length)), get_tag())

test_println("try to set length = 0", get_tag())
try:
    ipp3.length = 0
except:
    test_println("  {0} raised: {1}\n".format(sys.exc_info()[0], sys.exc_info()[1]), get_tag())

test_println("try to set IPv6 length = 129", get_tag())
try:
    ipp3.length = 129
except:
    test_println( "  {0} raised: {1}\n".format(sys.exc_info()[0], sys.exc_info()[1]), get_tag())

test_println("try to set IPv6 length = '4'", get_tag())
try:
    ipp3.length = '4'
except:
    test_println("  {0} raised: {1}\n".format(sys.exc_info()[0], sys.exc_info()[1]), get_tag())

test_println("try to set version = 5", get_tag())
try:
    ipp3.version = 5
except:
    test_println( "  {0} raised: {1}\n".format(sys.exc_info()[0], sys.exc_info()[1]), get_tag())

ippv4  = ipp.IPprefix(4, bytearray("5678", encoding='utf-8'), 32)
ippv4g = ipp.IPprefix(4, bytearray("90AB", encoding='utf-8'), 32)
ippv4l = ipp.IPprefix(4, bytearray("1234", encoding='utf-8'), 32)
ippv4p = ipp.IPprefix(4, bytearray("5678", encoding='utf-8'), 16)

test_println( "test compare", get_tag())
test_println( "4 lt 4l = {0}, {1} (T,F)".format(ippv4l < ippv4, ippv4 < ippv4l), get_tag())
test_println( "4 le:4l = {0}, {1} (T,F)".format(ippv4l <= ippv4, ippv4 <= ippv4l), get_tag())
test_println( "4 eq 4 = {0}, {1} (T,T)".format(ippv4 == ippv4, ippv4 == ippv4), get_tag())
test_println( "4 ne 4 = {0}, {1} (F,F)".format(ippv4 != ippv4, ippv4 != ippv4), get_tag())
test_println( "4g gt 4 = {0}, {1} (T,F)".format(ippv4g > ippv4, ippv4 > ippv4g), get_tag())
test_println( "4g ge 4 = {0}, {1} (T,F)\n".format(ippv4g >= ippv4, ippv4 >= ippv4g), get_tag())

test_println( "4p lt 4, 4p with longer prefix = {0}, {1} (T,F)".format(ippv4 < ippv4p, ippv4p < ippv4), get_tag())
test_println( "4p eq 4, 4p with longer prefix = {0}, {1} (F,F)\n".format(ippv4 == ippv4p, ippv4p == ippv4), get_tag())

test_println( "Test print v4 IPprefix objects", get_tag())
v4a = ipp.IPprefix(4, bytearray(b"\x82\xd8\x00\x01"))
v4b = ipp.IPprefix(4, bytearray(b"\x82\xd8\x01\x02"))
v4c = ipp.IPprefix(4, bytearray(b"\x02\xd8\x03\x02"))
v4d = ipp.IPprefix(4, bytearray(b"\x82\xd8\x04\x03"), 16)

test_println( "v4a = {0}".format(v4a), get_tag())
test_println( "v4b = {0}".format(v4b), get_tag())
test_println( "v4c = {0}".format(v4c), get_tag())
test_println( "v4d = {0}".format(v4d), get_tag())

test_println( "Test print v6 IPprefix objects", get_tag())  #  2001:0df0::/47
v6a = ipp.IPprefix(6, bytearray(b"\x20\x01\x0d\xf0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xab\xcd"))
v6b = ipp.IPprefix(6, bytearray(b"\x02\x00\x00\x01\x0d\x0d\x01\x02\x00\x00\x00\x00\x00\x00\xab\xcd"))
v6c = ipp.IPprefix(6, bytearray(b"\x02\x00\x00\x01\x0d\x0d\x07\x00\x00\x12\x00\x00\x00\x00\xab\xcd"), 120)
v6d = ipp.IPprefix(6, bytearray(b"\x20\x01\x0d\xf0\x0d\x0d\x00\x00\xde\xad\x00\x00\x00\x00\xab\xcd"), 47)

test_println( "v6a = {0}".format(v6a), get_tag())
test_println( "v6b = {0}".format(v6b), get_tag())
test_println( "v6c = {0}".format(v6c), get_tag())
test_println( "v6d = {0}\n".format(v6d), get_tag())

fs4 = ipp.from_s("130.216.1.1")
test_println( "fs4 = {0}".format(fs4), get_tag())
fs4s = ipp.from_s("130.216.1.1/16")
test_println( "fs4s = {0}".format(fs4s), get_tag())
fs6 = ipp.from_s("2001:0df0::00ef:0000:0000:0001")
test_println( "fs4 = {0}".format(fs6), get_tag())
fs6s = ipp.from_s("2001:0df0::/47")
test_println( "fs4s = {0}\n".format(fs6s), get_tag())

test_println( str(ipp.rfc1918s16), get_tag())
test_println( str(ipp.rfc1918s12), get_tag())
test_println( str(ipp.rfc1918s8), get_tag())

r1918_16 = ipp.from_s("192.168.1.1/24")
n1918_16 = ipp.from_s("192.169.1.1/24")

test_println( "{0} is_prefix {1}, {2} isp_refix {3} (T,F)\n".format(
   ipp.rfc1918s16, ipp.rfc1918s16.is_prefix(r1918_16),
   ipp.rfc1918s16, ipp.rfc1918s16.is_prefix(n1918_16)), get_tag())

test_println("r1918_16.isrfc1918 = {0} (T)".format(r1918_16.is_rfc1918()), get_tag())
test_println("n1918_16.isrfc1918 = {0} (F)".format(n1918_16.is_rfc1918()), get_tag())

r1918_12 = ipp.from_s("172.16.1.1/16")
r1918_8 = ipp.from_s("10.1.1.1/16")
r1918_8a = ipp.from_s("10.1.1.1/12")
r1918_12a = ipp.from_s("172.16.1.2/16")

test_println("r1918_12.isrfc1918 = {0} (T)".format(r1918_12.is_rfc1918()), get_tag())
test_println("r1918_8.isrfc1918 = {0} (T)\n".format(r1918_8.is_rfc1918()), get_tag())

test_println( "ipp.version = {0}\n".format(ipp.version()), get_tag())

zs = ipp.IPprefix(4, bytearray(b"12\x00\x51"))
test_println( "zs = {0} (49.50.0.81)\n".format(zs), get_tag())

test_println( "width(r1918_8) = %d (15)" % r1918_8.width(), get_tag())
test_println( "r1918_8.equal(r1918_8) = %s (T)" % r1918_8.equal(r1918_8), get_tag())
test_println( "r1918_8.equal(r1918_8a) = %s (T)" % r1918_8.equal(r1918_8a), get_tag())
test_println( "r1918_8.has_bit_set(4) = %s (T)" % r1918_8.has_bit_set(4), get_tag())
test_println( "r1918_8.has_bit_set(5) = %s (F)" % r1918_8.has_bit_set(5), get_tag())
test_println( "r1918_8.complement() = %s (245.254.254.254/16)" % r1918_8.complement(), get_tag())

a1 = ipp.from_s("172.16.1.1/32")
a2 = ipp.from_s("172.16.1.2/32")
test_println( "r1918_12.first_bit_different(r1918_12a) = %d (16)" % r1918_12.first_bit_different(r1918_12a), get_tag())
test_println( "a1.first_bit_different(a2) = %d (30)" % a1.first_bit_different(a2), get_tag())
