
import ipp
from plt_testing import *

ipa = ipp.from_s("1.2.3.4")  # 1
ipb = ipp.from_s("1.2.3.5")  # 2
ipc = ipp.from_s("1.2.4.4")  # 3
ipd = ipp.from_s("1.3.3.4")  # 4
ipe = ipp.from_s("2.2.3.4")  # 5

h = {ipa : 1, ipb : 2, ipc : 3, ipd : 4, ipe : 5}

for ip in sorted(h):
      test_println(str("%s -> %d,  %d" % (ip, h[ip], ip.__hash__())), get_tag())

ip01 = ipp.from_s("192.168.10.1/16")
test_println(str("ip01 =            %s" % ip01), get_tag())
test_println(str("ip01.complement = %s" % ip01.complement), get_tag())
test_println(str("ip01.width      = %d" % ip01.width), get_tag())
test_println(str("ip01.is_rfc1918 = %s" % ip01.is_rfc1918), get_tag())

ip88 = ipp.from_s("192.168.0.0/16")
ip89 = ipp.from_s("192.168.0.0")

def test_ip(ip):
    test_println(str("--- trying %s" % ip), get_tag())
    test_println(str("   slash: %s.is_prefix(%s) -> %s" % (
        ip88, ip, ip88.is_prefix(ip))), get_tag())
    r = ip.is_rfc1918
    test_println(str("%s -> %s" % (ip, r)), get_tag())

ip1 = ipp.from_s("130.216.12.34")
ip2 = ipp.from_s("130.216.56.78/32")
ip81 = ipp.from_s("192.168.0.2")
ip82 = ipp.from_s("192.168.1.3/32")

for j in range(1):
    test_ip(ip81)
    test_ip(ip82)
    test_ip(ip1)
    test_ip(ip2)

try:
    r = ip01 == "130.216.56.78"  # Argument is string, not IPprefix
except:
    test_println(str("Exception caught"), get_tag())
  
