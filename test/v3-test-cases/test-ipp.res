[<module>:9] 3: version=6, addr=b'01020304050607082c30783039008182', length=48
[<module>:12] 2: version=4, addr=b'c0a80000'
[<module>:15] 1: version=4

[<module>:17] ipp3 = 102:304:506:708:2c30:7830:3900:8182/48
[<module>:18] ipp2 = 192.168.0.0
[<module>:19] ipp1 = 0.0.0.0
[<module>:21] addrs: ipp3 = b'01020304050607082c30783039008182'   ipp2 = b'c0a80000'
[<module>:24] len=7: version=6, addr=b'01020304050607082c30783039008182', length=7

[<module>:26] try to set length = 0
[<module>:30]   <class 'ValueError'> raised: length must be > 0

[<module>:32] try to set IPv6 length = 129
[<module>:36]   <class 'ValueError'> raised: IPv6 length must be <= 128

[<module>:38] try to set IPv6 length = '4'
[<module>:42]   <class 'TypeError'> raised: length must be an integer

[<module>:44] try to set version = 5
[<module>:48]   <class 'AttributeError'> raised: version and addr are READONLY

[<module>:55] test compare
[<module>:56] 4 lt 4l = True, False (T,F)
[<module>:57] 4 le:4l = True, False (T,F)
[<module>:58] 4 eq 4 = True, True (T,T)
[<module>:59] 4 ne 4 = False, False (F,F)
[<module>:60] 4g gt 4 = True, False (T,F)
[<module>:61] 4g ge 4 = True, False (T,F)

[<module>:63] 4p lt 4, 4p with longer prefix = True, False (T,F)
[<module>:64] 4p eq 4, 4p with longer prefix = False, False (F,F)

[<module>:66] Test print v4 IPprefix objects
[<module>:72] v4a = 130.216.0.1
[<module>:73] v4b = 130.216.1.2
[<module>:74] v4c = 2.216.3.2
[<module>:75] v4d = 130.216.4.3/16
[<module>:77] Test print v6 IPprefix objects
[<module>:83] v6a = 2001:df0::abcd
[<module>:84] v6b = 200:1:d0d:102::abcd
[<module>:85] v6c = 200:1:d0d:700:12::abcd/120
[<module>:86] v6d = 2001:df0:d0d:0:dead::abcd/47

[<module>:89] fs4 = 130.216.1.1
[<module>:91] fs4s = 130.216.1.1/16
[<module>:93] fs4 = 2001:df0::ef:0:0:1
[<module>:95] fs4s = 2001:df0::/47

[<module>:97] 192.168.0.0/16
[<module>:98] 172.16.0.0/12
[<module>:99] 10.0.0.0/8
[<module>:106] 192.168.0.0/16 is_prefix True, 192.168.0.0/16 isp_refix False (T,F)

[<module>:108] r1918_16.isrfc1918 = True (T)
[<module>:109] n1918_16.isrfc1918 = False (F)
[<module>:116] r1918_12.isrfc1918 = True (T)
[<module>:117] r1918_8.isrfc1918 = True (T)

[<module>:119] ipp.version = 1.9

[<module>:122] zs = 49.50.0.81 (49.50.0.81)

[<module>:124] width(r1918_8) = 15 (15)
[<module>:125] r1918_8.equal(r1918_8) = True (T)
[<module>:126] r1918_8.equal(r1918_8a) = True (T)
[<module>:127] r1918_8.has_bit_set(4) = True (T)
[<module>:128] r1918_8.has_bit_set(5) = False (F)
[<module>:129] r1918_8.complement() = 245.254.254.254/16 (245.254.254.254/16)
[<module>:133] r1918_12.first_bit_different(r1918_12a) = 16 (16)
[<module>:134] a1.first_bit_different(a2) = 30 (30)
