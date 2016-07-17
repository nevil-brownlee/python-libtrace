[get_example_trace:23]fn = icmp6-sample.pcap

[<module>:19]     1: 
[<module>:20:{n:1}][print_icmp6:139]         ICMP6: stype=135, code=0, checksum=c165, wlen=90, clen=86, 2014-01-10 13:18:23.839870
[<module>:20:{n:1}][print_icmp6:185]            Neighbour Solicitation: target_prefix=2404:138:0:2::251, src_prefix=fe80::215:c7ff:fe56:8000
[<module>:20:{n:1}][print_icmp6:191][print_data:32]              Data 24 04 01 38 00 00 00 02   00 00 00 00 00 00 02 51   01 01 00 15 c7 56 80 00
 
[<module>:19]     2: 
[<module>:20:{n:2}][print_icmp6:139]         ICMP6: stype=135, code=0, checksum=5ecd, wlen=90, clen=86, 2014-01-10 13:18:23.953183
[<module>:20:{n:2}][print_icmp6:185]            Neighbour Solicitation: target_prefix=2404:138:0:1::154, src_prefix=fe80::8271:1f03:84c2:9700
[<module>:20:{n:2}][print_icmp6:191][print_data:32]              Data 24 04 01 38 00 00 00 01   00 00 00 00 00 00 01 54   01 01 80 71 1f c2 97 00
 
[<module>:19]     3: 
[<module>:20:{n:3}][print_icmp6:139]         ICMP6: stype=135, code=0, checksum=5ecd, wlen=90, clen=86, 2014-01-10 13:18:23.953198
[<module>:20:{n:3}][print_icmp6:185]            Neighbour Solicitation: target_prefix=2404:138:0:1::154, src_prefix=fe80::8271:1f03:84c2:9700
[<module>:20:{n:3}][print_icmp6:191][print_data:32]              Data 24 04 01 38 00 00 00 01   00 00 00 00 00 00 01 54   01 01 80 71 1f c2 97 00
 
[<module>:19]     4: 
[<module>:20:{n:4}][print_icmp6:139]         ICMP6: stype=135, code=0, checksum=6151, wlen=90, clen=86, 2014-01-10 13:18:23.953333
[<module>:20:{n:4}][print_icmp6:185]            Neighbour Solicitation: target_prefix=2404:138:0:1::12, src_prefix=fe80::8271:1f03:84c2:9700
[<module>:20:{n:4}][print_icmp6:191][print_data:32]              Data 24 04 01 38 00 00 00 01   00 00 00 00 00 00 00 12   01 01 80 71 1f c2 97 00
 
[<module>:19]     5: 
[<module>:20:{n:5}][print_icmp6:139]         ICMP6: stype=128, code=0, checksum=f28c, wlen=78, clen=74, 2014-01-10 13:18:25.686030
[<module>:20:{n:5}]            Echo request: ident=f28c, sequence=11
[<module>:20:{n:5}][print_icmp6:191][print_data:32]              Data c6 24 00 00 00 00 00 00   00 00 00 00
 
[<module>:19]     6: 
[<module>:20:{n:6}][print_icmp6:139]         ICMP6: stype=1, code=1, checksum=17cf, wlen=174, clen=170, 2014-01-10 13:18:25.798298
[<module>:20:{n:6}][print_icmp6:145]            Destination unreachable: [print_ip6_info:133] 2001:500:2d::d -> 2001:df0:0:202a::237, TTL=56
[<module>:20:{n:6}][print_icmp6:191][print_data:32]              IP6  60 00 00 00 00 44 11 05   20 01 0d f0 00 00 20 2a   00 00 00 00 00 00 02 37   20 01 05 00 00 2d 00 00 
[<module>:20:{n:6}][print_icmp6:191][print_data:37]                 00 00 00 00 00 00 00 0d   cb 09 82 9a 00 44 92 2c   38 1c 71 ec 00 00 00 00   00 00 00 00 00 00 00 00
 
[<module>:19]     7: 
[<module>:20:{n:7}][print_icmp6:139]         ICMP6: stype=3, code=0, checksum=f473, wlen=174, clen=170, 2014-01-10 13:18:25.925637
[<module>:20:{n:7}][print_icmp6:162]            Time Exceeded: [print_ip6_info:133] 2001:450:2002:247::1 -> 2001:df0:0:202a::237, TTL=55
[<module>:20:{n:7}][print_icmp6:191][print_data:32]              IP6  60 00 00 00 00 44 11 01   20 01 0d f0 00 00 20 2a   00 00 00 00 00 00 02 37   20 01 05 02 2e da 00 00 
[<module>:20:{n:7}][print_icmp6:191][print_data:37]                 00 00 00 00 00 00 00 14   cb 09 82 9a 00 44 3b 3f   60 53 71 ec 00 00 00 00   00 00 00 00 00 00 00 00
 
[<module>:19]     8: 
[<module>:20:{n:8}][print_icmp6:139]         ICMP6: stype=128, code=0, checksum=f28c, wlen=78, clen=74, 2014-01-10 13:18:25.935520
[<module>:20:{n:8}]            Echo request: ident=f28c, sequence=18
[<module>:20:{n:8}][print_icmp6:191][print_data:32]              Data a6 29 00 00 00 00 00 00   00 00 00 00
 
[<module>:19]     9: 
[<module>:20:{n:9}][print_icmp6:139]         ICMP6: stype=3, code=0, checksum=00d5, wlen=174, clen=170, 2014-01-10 13:18:26.190115
[<module>:20:{n:9}][print_icmp6:162]            Time Exceeded: [print_ip6_info:133] 2001:1900:5:3::131 -> 2001:df0:0:202a::237, TTL=57
[<module>:20:{n:9}][print_icmp6:191][print_data:32]              IP6  60 00 00 00 00 44 11 01   20 01 0d f0 00 00 20 2a   00 00 00 00 00 00 02 37   20 01 05 02 2e da 00 00 
[<module>:20:{n:9}][print_icmp6:191][print_data:37]                 00 00 00 00 00 00 00 14   cb 09 82 9a 00 44 37 3f   64 53 71 ec 00 00 00 00   00 00 00 00 00 00 00 00
 
[<module>:19]    10: 
[<module>:20:{n:10}][print_icmp6:139]         ICMP6: stype=128, code=0, checksum=f28c, wlen=78, clen=74, 2014-01-10 13:18:26.388974
[<module>:20:{n:10}]            Echo request: ident=f28c, sequence=10
[<module>:20:{n:10}][print_icmp6:191][print_data:32]              Data 23 97 00 00 00 00 00 00   00 00 00 00
 
[<module>:19]    11: 
[<module>:20:{n:11}][print_icmp6:139]         ICMP6: stype=136, code=0, checksum=4c5a, wlen=82, clen=78, 2014-01-10 13:18:26.509678
[<module>:20:{n:11}][print_icmp6:185]            Neighbour Advertisment: target_prefix=fe80::ce3e:5fff:fe2e:6744, src_prefix=fe80::ce3e:5fff:fe2e:6744
[<module>:20:{n:11}][print_icmp6:191][print_data:32]              Data fe 80 00 00 00 00 00 00   ce 3e 5f ff fe 2e 67 44
 
[<module>:19]    12: 
[<module>:20:{n:12}][print_icmp6:139]         ICMP6: stype=136, code=0, checksum=244a, wlen=82, clen=78, 2014-01-10 13:18:28.442647
[<module>:20:{n:12}][print_icmp6:185]            Neighbour Advertisment: target_prefix=fe80::215:c7ff:fe23:df80, src_prefix=fe80::215:c7ff:fe23:df80
[<module>:20:{n:12}][print_icmp6:191][print_data:32]              Data fe 80 00 00 00 00 00 00   02 15 c7 ff fe 23 df 80
 
[<module>:19]    13: 
[<module>:20:{n:13}][print_icmp6:139]         ICMP6: stype=136, code=0, checksum=ce4b, wlen=82, clen=78, 2014-01-10 13:18:28.455127
[<module>:20:{n:13}][print_icmp6:185]            Neighbour Advertisment: target_prefix=fe80::a236:9fff:fe15:d26c, src_prefix=fe80::a236:9fff:fe15:d26c
[<module>:20:{n:13}][print_icmp6:191][print_data:32]              Data fe 80 00 00 00 00 00 00   a2 36 9f ff fe 15 d2 6c
 
[<module>:19]    14: 
[<module>:20:{n:14}][print_icmp6:139]         ICMP6: stype=136, code=0, checksum=c73b, wlen=82, clen=78, 2014-01-10 13:18:28.458823
[<module>:20:{n:14}][print_icmp6:185]            Neighbour Advertisment: target_prefix=fe80::a236:9fff:fe15:d5f4, src_prefix=fe80::a236:9fff:fe15:d5f4
[<module>:20:{n:14}][print_icmp6:191][print_data:32]              Data fe 80 00 00 00 00 00 00   a2 36 9f ff fe 15 d5 f4
 
[<module>:19]    15: 
[<module>:20:{n:15}][print_icmp6:139]         ICMP6: stype=128, code=0, checksum=61d0, wlen=102, clen=98, 2014-01-10 13:18:30.201852
[<module>:20:{n:15}]            Echo request: ident=aef0, sequence=164
[<module>:20:{n:15}][print_icmp6:191][print_data:32]              Data 9a 87 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00 
[<module>:20:{n:15}][print_icmp6:191][print_data:37]                 00 00 00 00
 
[<module>:19]    16: 
[<module>:20:{n:16}][print_icmp6:139]         ICMP6: stype=129, code=0, checksum=60d0, wlen=102, clen=98, 2014-01-10 13:18:30.201896
[<module>:20:{n:16}]            Echo reply:   ident=aef0, sequence=164
[<module>:20:{n:16}][print_icmp6:191][print_data:32]              Data 9a 87 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00 
[<module>:20:{n:16}][print_icmp6:191][print_data:37]                 00 00 00 00
 
[<module>:19]    17: 
[<module>:20:{n:17}][print_icmp6:139]         ICMP6: stype=129, code=0, checksum=4ba2, wlen=102, clen=98, 2014-01-10 13:18:30.207986
[<module>:20:{n:17}]            Echo reply:   ident=c41e, sequence=164
[<module>:20:{n:17}][print_icmp6:191][print_data:32]              Data 9a 87 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00 
[<module>:20:{n:17}][print_icmp6:191][print_data:37]                 00 00 00 00
 
[<module>:19]    18: 
[<module>:20:{n:18}][print_icmp6:139]         ICMP6: stype=129, code=0, checksum=7d18, wlen=102, clen=98, 2014-01-10 13:18:30.378517
[<module>:20:{n:18}]            Echo reply:   ident=351c, sequence=156
[<module>:20:{n:18}][print_icmp6:191][print_data:32]              Data 59 3c 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00 
[<module>:20:{n:18}][print_icmp6:191][print_data:37]                 00 00 00 00
 
[<module>:19]    19: 
[<module>:20:{n:19}][print_icmp6:139]         ICMP6: stype=129, code=0, checksum=2741, wlen=102, clen=98, 2014-01-10 13:18:30.692096
[<module>:20:{n:19}]            Echo reply:   ident=24ee, sequence=161
[<module>:20:{n:19}][print_icmp6:191][print_data:32]              Data a5 6f 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00 
[<module>:20:{n:19}][print_icmp6:191][print_data:37]                 00 00 00 00
 
[<module>:19]    20: 
[<module>:20:{n:20}][print_icmp6:139]         ICMP6: stype=3, code=0, checksum=f493, wlen=142, clen=138, 2014-01-10 13:18:31.494280
[<module>:20:{n:20}][print_icmp6:162]            Time Exceeded: [print_ip6_info:133] 2001:450:2002:247::1 -> 2001:df0:0:202a::237, TTL=55
[<module>:20:{n:20}][print_icmp6:191][print_data:32]              IP6  60 00 00 00 00 24 11 01   20 01 0d f0 00 00 20 2a   00 00 00 00 00 00 02 37   20 01 05 02 2e da 00 00 
[<module>:20:{n:20}][print_icmp6:191][print_data:37]                 00 00 00 00 00 00 00 14   92 d3 00 35 00 24 a3 ce   cd 5f 00 00 00 01 00 00   00 00 00 00 03 64 6e 73
 
[<module>:19]    21: 
[<module>:20:{n:21}][print_icmp6:139]         ICMP6: stype=3, code=0, checksum=010a, wlen=174, clen=170, 2014-01-10 13:18:31.636037
[<module>:20:{n:21}][print_icmp6:162]            Time Exceeded: [print_ip6_info:133] 2001:1900:101:1::2 -> 2001:df0:0:202a::237, TTL=57
[<module>:20:{n:21}][print_icmp6:191][print_data:32]              IP6  60 00 00 00 00 44 11 01   20 01 0d f0 00 00 20 2a   00 00 00 00 00 00 02 37   20 01 05 02 2e da 00 00 
[<module>:20:{n:21}][print_icmp6:191][print_data:37]                 00 00 00 00 00 00 00 14   cb 09 82 9a 00 44 33 3f   68 53 71 ec 00 00 00 00   00 00 00 00 00 00 00 00
 
[<module>:19]    22: 
[<module>:20:{n:22}][print_icmp6:139]         ICMP6: stype=1, code=4, checksum=17c5, wlen=174, clen=170, 2014-01-10 13:18:31.862566
[<module>:20:{n:22}][print_icmp6:145]            Destination unreachable: [print_ip6_info:133] 2001:500:3::42 -> 2001:df0:0:202a::237, TTL=253
[<module>:20:{n:22}][print_icmp6:191][print_data:32]              IP6  60 00 00 00 00 44 11 01   20 01 0d f0 00 00 20 2a   00 00 00 00 00 00 02 37   20 01 05 00 00 03 00 00 
[<module>:20:{n:22}][print_icmp6:191][print_data:37]                 00 00 00 00 00 00 00 42   d5 9f 82 9a 00 44 cb 39   10 0e 56 4c 00 00 00 00   00 00 00 00 00 00 00 00
 
[<module>:19]    23: 
[<module>:20:{n:23}][print_icmp6:139]         ICMP6: stype=1, code=1, checksum=88bb, wlen=174, clen=170, 2014-01-10 13:18:32.011419
[<module>:20:{n:23}][print_icmp6:145]            Destination unreachable: [print_ip6_info:133] 2407:9000:10:38::2 -> 2001:df0:0:202a::237, TTL=56
[<module>:20:{n:23}][print_icmp6:191][print_data:32]              IP6  60 00 00 00 00 44 11 02   20 01 0d f0 00 00 20 2a   00 00 00 00 00 00 02 37   20 01 0d c0 20 01 00 11 
[<module>:20:{n:23}][print_icmp6:191][print_data:37]                 00 00 00 00 00 00 01 75   d5 9f 82 9a 00 44 95 41   1c 04 56 4c 00 00 00 00   00 00 00 00 00 00 00 00
 
[<module>:19]    24: 
[<module>:20:{n:24}][print_icmp6:139]         ICMP6: stype=1, code=4, checksum=1d0e, wlen=774, clen=770, 2014-01-10 13:18:32.708321
[<module>:20:{n:24}][print_icmp6:145]            Destination unreachable: [print_ip6_info:133] 2001:df0:0:2022:214:5eff:fe7e:9528 -> 2001:678:18:0:194:190:124:17, TTL=62
[<module>:20:{n:24}][print_icmp6:191][print_data:32]              IP6  60 00 00 00 02 9c 11 3a   20 01 06 78 00 18 00 00   01 94 01 90 01 24 00 17   20 01 0d f0 00 00 20 22 
[<module>:20:{n:24}][print_icmp6:191][print_data:37]                 02 14 5e ff fe 7e 95 28   00 35 04 16 02 9c 99 43   e1 28 80 10 00 01 00 00   00 08 00 05 03 6e 73 33
 
[<module>:19]    25: 
[<module>:20:{n:25}][print_icmp6:139]         ICMP6: stype=4, code=1, checksum=5afa, wlen=126, clen=122, 2014-01-10 13:18:41.296089
[<module>:20:{n:25}][print_icmp6:166]            Parameter Problem; pointer=14, [print_ip6_info:133] 2600:1415:1::b854:df58 -> 2001:df0:0:200e:ca1f:66ff:fea7:eac3, TTL=53
[<module>:20:{n:25}][print_icmp6:191][print_data:32]              IP6  60 00 00 00 00 14 06 30   20 01 0d f0 00 00 20 0e   ca 1f 66 ff fe a7 ea c3   26 00 14 15 00 01 00 01 
[<module>:20:{n:25}][print_icmp6:191][print_data:37]                 86 00 00 00 00 00 02 36   c3 71 01 bb 0b 2f 61 fb   0b 2f 61 fb 50 04 00 00   e5 87 00 00
 
[<module>:19]    26: 
[<module>:20:{n:26}][print_icmp6:139]         ICMP6: stype=4, code=1, checksum=5afa, wlen=126, clen=122, 2014-01-10 13:18:45.033124
[<module>:20:{n:26}][print_icmp6:166]            Parameter Problem; pointer=14, [print_ip6_info:133] 2600:1415:1::b854:df58 -> 2001:df0:0:200e:ca1f:66ff:fea7:eac3, TTL=53
[<module>:20:{n:26}][print_icmp6:191][print_data:32]              IP6  60 00 00 00 00 14 06 30   20 01 0d f0 00 00 20 0e   ca 1f 66 ff fe a7 ea c3   26 00 14 15 00 01 00 01 
[<module>:20:{n:26}][print_icmp6:191][print_data:37]                 86 00 00 00 00 00 02 36   c3 71 01 bb 0b 2f 61 fb   0b 2f 61 fb 50 04 00 00   e5 87 00 00
 
[<module>:19]    27: 
[<module>:20:{n:27}][print_icmp6:139]         ICMP6: stype=4, code=1, checksum=5afa, wlen=126, clen=122, 2014-01-10 13:18:52.506191
[<module>:20:{n:27}][print_icmp6:166]            Parameter Problem; pointer=14, [print_ip6_info:133] 2600:1415:1::b854:df58 -> 2001:df0:0:200e:ca1f:66ff:fea7:eac3, TTL=53
[<module>:20:{n:27}][print_icmp6:191][print_data:32]              IP6  60 00 00 00 00 14 06 30   20 01 0d f0 00 00 20 0e   ca 1f 66 ff fe a7 ea c3   26 00 14 15 00 01 00 01 
[<module>:20:{n:27}][print_icmp6:191][print_data:37]                 86 00 00 00 00 00 02 36   c3 71 01 bb 0b 2f 61 fb   0b 2f 61 fb 50 04 00 00   e5 87 00 00
 
[<module>:19]    28: 
[<module>:20:{n:28}][print_icmp6:139]         ICMP6: stype=134, code=0, checksum=aa0d, wlen=122, clen=118, 2014-01-10 13:19:03.972249
[<module>:20:{n:28}][print_icmp6:188]            Router Advertisment: src_prefix=fe80::c67d:4fff:fe87:402
[<module>:20:{n:28}][print_icmp6:191][print_data:32]              Data 00 00 00 00 00 00 00 00   01 01 c4 7d 4f 87 04 02   05 01 00 00 00 00 23 28   03 04 40 c0 00 27 8d 00 
[<module>:20:{n:28}][print_icmp6:191][print_data:37]                 00 09 3a 80 00 00 00 00   24 04 01 38 00 00 00 01   00 00 00 00 00 00 00 00
 
[<module>:19]    29: 
[<module>:20:{n:29}][print_icmp6:139]         ICMP6: stype=4, code=1, checksum=5afa, wlen=126, clen=122, 2014-01-10 13:19:07.480184
[<module>:20:{n:29}][print_icmp6:166]            Parameter Problem; pointer=14, [print_ip6_info:133] 2600:1415:1::b854:df58 -> 2001:df0:0:200e:ca1f:66ff:fea7:eac3, TTL=53
[<module>:20:{n:29}][print_icmp6:191][print_data:32]              IP6  60 00 00 00 00 14 06 30   20 01 0d f0 00 00 20 0e   ca 1f 66 ff fe a7 ea c3   26 00 14 15 00 01 00 01 
[<module>:20:{n:29}][print_icmp6:191][print_data:37]                 86 00 00 00 00 00 02 36   c3 71 01 bb 0b 2f 61 fb   0b 2f 61 fb 50 04 00 00   e5 87 00 00
 
[<module>:19]    30: 
[<module>:20:{n:30}][print_icmp6:139]         ICMP6: stype=134, code=0, checksum=424b, wlen=122, clen=118, 2014-01-10 13:19:26.965145
[<module>:20:{n:30}][print_icmp6:188]            Router Advertisment: src_prefix=fe80::225:45ff:fe04:6bf
[<module>:20:{n:30}][print_icmp6:191][print_data:32]              Data 00 00 00 00 00 00 00 00   01 01 00 25 45 04 06 bf   05 01 00 00 00 00 23 28   03 04 40 c0 00 27 8d 00 
[<module>:20:{n:30}][print_icmp6:191][print_data:37]                 00 09 3a 80 00 00 00 00   24 04 01 38 00 00 00 01   00 00 00 00 00 00 00 00
 
[<module>:19]    31: 
[<module>:20:{n:31}][print_icmp6:139]         ICMP6: stype=134, code=0, checksum=424b, wlen=122, clen=118, 2014-01-10 13:19:26.965397
[<module>:20:{n:31}][print_icmp6:188]            Router Advertisment: src_prefix=fe80::225:45ff:fe04:6bf
[<module>:20:{n:31}][print_icmp6:191][print_data:32]              Data 00 00 00 00 00 00 00 00   01 01 00 25 45 04 06 bf   05 01 00 00 00 00 23 28   03 04 40 c0 00 27 8d 00 
[<module>:20:{n:31}][print_icmp6:191][print_data:37]                 00 09 3a 80 00 00 00 00   24 04 01 38 00 00 00 01   00 00 00 00 00 00 00 00
 
[<module>:19]    32: 
[<module>:20:{n:32}][print_icmp6:139]         ICMP6: stype=134, code=0, checksum=5998, wlen=122, clen=118, 2014-01-10 13:19:31.517601
[<module>:20:{n:32}][print_icmp6:188]            Router Advertisment: src_prefix=fe80::21b:90ff:fe0d:3019
[<module>:20:{n:32}][print_icmp6:191][print_data:32]              Data 00 00 00 00 00 00 00 00   01 01 00 1b 90 0d 30 19   05 01 00 00 00 00 23 28   03 04 40 c0 00 27 8d 00 
[<module>:20:{n:32}][print_icmp6:191][print_data:37]                 00 09 3a 80 00 00 00 00   24 04 01 38 00 00 00 01   00 00 00 00 00 00 00 00
 
[<module>:19]    33: 
[<module>:20:{n:33}][print_icmp6:139]         ICMP6: stype=2, code=0, checksum=31dd, wlen=1298, clen=1294, 2014-01-10 14:20:02.157429
[<module>:20:{n:33}][print_icmp6:158]            Packet Too Big; MTU=1496: [print_ip6_info:133] ::ffff:207.46.46.121 -> 2001:df0:0:2027:31db:eb60:85d:9d2e, TTL=40
[<module>:20:{n:33}][print_icmp6:191][print_data:32]              IP   60 00 00 00 05 b4 06 38   20 01 0d f0 00 00 20 27   31 db eb 60 08 5d 9d 2e   2a 01 01 11 20 0f 00 00 
[<module>:20:{n:33}][print_icmp6:191][print_data:37]                 00 00 00 00 00 00 00 a1   f9 c5 01 bb e9 e7 a9 c3   88 09 ea 1b 50 10 01 02   15 1f 00 00 17 03 03 10
 
[<module>:19]    34: 
[<module>:20:{n:34}][print_icmp6:139]         ICMP6: stype=2, code=0, checksum=1910, wlen=1298, clen=1294, 2014-01-10 16:21:13.419852
[<module>:20:{n:34}][print_icmp6:158]            Packet Too Big; MTU=1496: [print_ip6_info:133] ::ffff:207.46.47.155 -> 2001:df0:0:2027:808f:f949:8e11:6086, TTL=41
[<module>:20:{n:34}][print_icmp6:191][print_data:32]              IP   60 00 00 00 05 b4 06 38   20 01 0d f0 00 00 20 27   80 8f f9 49 8e 11 60 86   2a 01 01 11 20 0f 00 00 
[<module>:20:{n:34}][print_icmp6:191][print_data:37]                 00 00 00 00 00 00 00 a1   41 87 01 bb 71 c8 58 21   f5 f3 83 4c 50 10 01 02   e9 bb 00 00 17 03 03 0d
 
[<module>:19]    35: 
[<module>:20:{n:35}][print_icmp6:139]         ICMP6: stype=2, code=0, checksum=6e00, wlen=1298, clen=1294, 2014-01-10 16:24:39.737047
[<module>:20:{n:35}][print_icmp6:158]            Packet Too Big; MTU=1480: [print_ip6_info:133] 2001:328:2000:1000:c1::26 -> 2001:df0:0:1000::10, TTL=52
[<module>:20:{n:35}][print_icmp6:191][print_data:32]              IP   60 00 00 00 05 b4 06 36   20 01 0d f0 00 00 10 00   00 00 00 00 00 00 00 10   20 01 03 28 20 0c 00 31 
[<module>:20:{n:35}][print_icmp6:191][print_data:37]                 8d 4e 6c 57 cb 81 42 a6   01 bb c2 9d b2 32 08 2e   cf 0d 2f 61 50 10 10 e0   fc 72 00 00 16 03 03 00
 
[<module>:19]    36: 
[<module>:20:{n:36}][print_icmp6:139]         ICMP6: stype=2, code=0, checksum=9aaf, wlen=1298, clen=1294, 2014-01-10 16:24:39.738295
[<module>:20:{n:36}][print_icmp6:158]            Packet Too Big; MTU=1480: [print_ip6_info:133] 2001:328:2000:1000:c1::26 -> 2001:df0:0:1000::10, TTL=52
[<module>:20:{n:36}][print_icmp6:191][print_data:32]              IP   60 00 00 00 05 b4 06 36   20 01 0d f0 00 00 10 00   00 00 00 00 00 00 00 10   20 01 03 28 20 0c 00 31 
[<module>:20:{n:36}][print_icmp6:191][print_data:37]                 8d 4e 6c 57 cb 81 42 a6   01 bb c2 9d b2 32 0d ce   cf 0d 2f 61 50 10 10 e0   95 89 00 00 82 7c 9e 5e
 
