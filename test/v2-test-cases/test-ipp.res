[<module>:9] 3: version=6, addr=01020304050607082c30783039008182, length=48
[<module>:12] 2: version=4, addr=c0a80000
[<module>:15] 1: version=4

[<module>:17] ipp3 = 102:304:506:708:2c30:7830:3900:8182/48
[<module>:18] ipp2 = 192.168.0.0
[<module>:19] ipp1 = 0.0.0.0
[<module>:21] addrs: ipp3 = 01020304050607082c30783039008182   ipp2 = c0a80000
[<module>:24] len=7: version=6, addr=01020304050607082c30783039008182, length=7

[<module>:26] try to set length = 0
[<module>:30]   <type 'exceptions.ValueError'> raised: length must be > 0

[<module>:33] try to set IPv6 length = 129
[<module>:37]   <type 'exceptions.ValueError'> raised: IPv6 length must be <= 128

[<module>:40] try to set IPv6 length = '4'
[<module>:44]   <type 'exceptions.TypeError'> raised: length must be an integer

[<module>:47] try to set version = 5
[<module>:51]   <type 'exceptions.AttributeError'> raised: version and addr are READONLY

[<module>:59] test compare
[<module>:60] 4 lt 4l = True, False (T,F)
[<module>:61] 4 le:4l = True, False (T,F)
[<module>:62] 4 eq 4 = True, True (T,T)
[<module>:63] 4 ne 4 = False, False (F,F)
[<module>:64] 4g gt 4 = True, False (T,F)
[<module>:65] 4g ge 4 = True, False (T,F)

[<module>:67] 4p lt 4, 4p with longer prefix = True, False (T,F)
[<module>:68] 4p eq 4, 4p with longer prefix = False, False (F,F)

[<module>:70] Test print v4 IPprefix objects
[<module>:76] v4a = 130.216.0.1
[<module>:77] v4b = 130.216.1.2
[<module>:78] v4c = 2.216.3.2
[<module>:79] v4d = 130.216.4.3/16
[<module>:81] Test print v6 IPprefix objects
[<module>:87] v6a = 2001:df0::abcd
[<module>:88] v6b = 200:1:d0d:102::abcd
[<module>:89] v6c = 200:1:d0d:700:12::abcd/120
[<module>:90] v6d = 2001:df0:d0d:0:dead::abcd/47

[<module>:93] fs4 = 130.216.1.1
[<module>:95] fs4s = 130.216.1.1/16
[<module>:97] fs4 = 2001:df0::ef:0:0:1
[<module>:99] fs4s = 2001:df0::/47

[<module>:101] 192.168.0.0/16
[<module>:102] 172.16.0.0/12
[<module>:103] 10.0.0.0/8
[<module>:110] 192.168.0.0/16 is_prefix True, 192.168.0.0/16 isp_refix False (T,F)

[<module>:111] r1918_16.isrfc1918 = True (T)
[<module>:112] n1918_16.isrfc1918 = False (F)
[<module>:119] r1918_12.isrfc1918 = True (T)
[<module>:120] r1918_8.isrfc1918 = True (T)

[<module>:122] ipp.version = 1.9

[<module>:125] zs = 49.50.0.81 (49.50.0.81)

[<module>:127] width(r1918_8) = 15 (15)
[<module>:128] r1918_8.equal(r1918_8) = True (T)
[<module>:129] r1918_8.equal(r1918_8a) = True (T)
[<module>:130] r1918_8.has_bit_set(4) = True (T)
[<module>:131] r1918_8.has_bit_set(5) = False (F)
[<module>:132] r1918_8.complement() = 245.254.254.254/16 (245.254.254.254/16)
[<module>:136] r1918_12.first_bit_different(r1918_12a) = 16 (16)
[<module>:137] a1.first_bit_different(a2) = 30 (30)
