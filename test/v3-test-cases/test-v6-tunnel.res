[get_example_trace:23]fn = tunnel.pcap

[<module>:24]     1: 
[<module>:25:{n:1}][print_ip6:54] 2001:5c0:1000:a:8000:0:82d8:262d -> 2404:6800:4006:806::1016, proto=6, tclass=0,
[<module>:25:{n:1}][print_ip6:56]             ttl=128, hlen=None, plen=None flow_label=0, payload_len=1240, next_hdr=6
[<module>:30:{n:1}][print_tcp:75] TCP, 2001:5c0:1000:a:8000:0:82d8:262d -> 2404:6800:4006:806::1016, 56258 -> 443, seq=2290525500, ack=1115370550
[<module>:30:{n:1}][print_tcp:78]          flags=10 (A), window=257, checksum=5671, urg_ptr=0
[<module>:30:{n:1}][print_tcp:85][print_data:32]  
[<module>:30:{n:1}][print_tcp:85]          payload: 17 03 03 0e 72 00 00 00   00 00 00 00 03 06 77 8d   97 03 cd 24 37 d4 13 1f   42 cd 86 c8 86 96 ca b9
[<module>:30:{n:1}][print_tcp:85][print_data:37]              fa 1f 16 6e 7c f0 49 5c   31 70 b1 4e 58 9c d0 eb   0d ca cb 7e de 03 6e 98   50 57 8b 6f 44 f5 16 dd
[<module>:24]     2: 
[<module>:25:{n:2}][print_ip6:54] 2001:5c0:1000:a:8000:0:82d8:262d -> 2404:6800:4006:806::1016, proto=6, tclass=0,
[<module>:25:{n:2}][print_ip6:56]             ttl=128, hlen=None, plen=None flow_label=0, payload_len=1240, next_hdr=6
[<module>:30:{n:2}][print_tcp:75] TCP, 2001:5c0:1000:a:8000:0:82d8:262d -> 2404:6800:4006:806::1016, 56258 -> 443, seq=2290526720, ack=1115370550
[<module>:30:{n:2}][print_tcp:78]          flags=10 (A), window=257, checksum=efe, urg_ptr=0
[<module>:30:{n:2}][print_tcp:85][print_data:32]  
[<module>:30:{n:2}][print_tcp:85]          payload: 6d 0f 47 4a 42 af 66 72   74 dd 56 d9 54 60 30 3a   32 98 f4 f5 0e 32 93 cb   9c 11 6a 40 bf b9 b1 77
[<module>:30:{n:2}][print_tcp:85][print_data:37]              1e 51 d8 c1 50 99 d3 96   d2 03 c7 67 89 14 81 63   3e 0e 76 fe 15 8b e9 d8   f8 be 72 35 e9 cf 8a 8e
[<module>:24]     3: 
[<module>:25:{n:3}][print_ip6:54] 2001:5c0:1000:a:8000:0:82d8:262d -> 2404:6800:4006:806::1016, proto=6, tclass=0,
[<module>:25:{n:3}][print_ip6:56]             ttl=128, hlen=None, plen=None flow_label=0, payload_len=1240, next_hdr=6
[<module>:30:{n:3}][print_tcp:75] TCP, 2001:5c0:1000:a:8000:0:82d8:262d -> 2404:6800:4006:806::1016, 56258 -> 443, seq=2290527940, ack=1115370550
[<module>:30:{n:3}][print_tcp:78]          flags=10 (A), window=257, checksum=467e, urg_ptr=0
[<module>:30:{n:3}][print_tcp:85][print_data:32]  
[<module>:30:{n:3}][print_tcp:85]          payload: a4 73 0f 0c b7 b9 49 aa   df ce 8b 08 a3 f2 e6 3a   7a 90 42 e2 e6 de d1 64   d8 c9 c9 29 19 4b ca b0
[<module>:30:{n:3}][print_tcp:85][print_data:37]              09 df 77 a7 23 63 91 6b   8a 77 0a ea 99 da 18 e3   bc 43 77 b1 14 4f ab 08   2a f8 94 3b 1c 23 8d fc
[<module>:24]     4: 
[<module>:25:{n:4}][print_ip6:54] 2001:5c0:1000:a:8000:0:82d8:262d -> 2404:6800:4006:806::1016, proto=6, tclass=0,
[<module>:25:{n:4}][print_ip6:56]             ttl=128, hlen=None, plen=None flow_label=0, payload_len=63, next_hdr=6
[<module>:30:{n:4}][print_tcp:75] TCP, 2001:5c0:1000:a:8000:0:82d8:262d -> 2404:6800:4006:806::1016, 56258 -> 443, seq=2290529160, ack=1115370550
[<module>:30:{n:4}][print_tcp:78]          flags=18 (PA), window=257, checksum=4309, urg_ptr=0
[<module>:30:{n:4}][print_tcp:85][print_data:32]  
[<module>:30:{n:4}][print_tcp:85]          payload: 4c d7 5b 46 e9 de ee e1   ed 95 f5 2f e3 95 5c 08   89 b2 69 16 f7 6c 6d 62   fc 7f 11 32 1d 44 17 1c
[<module>:30:{n:4}][print_tcp:85][print_data:37]              89 05 d5 17 9d 96 89 e9   8b d6 4a
[<module>:24]     5: 
[<module>:25:{n:5}][print_ip6:54] 2001:5c0:1000:a:8000:0:82d8:262d -> 2404:6800:4006:806::1016, proto=6, tclass=0,
[<module>:25:{n:5}][print_ip6:56]             ttl=128, hlen=None, plen=None flow_label=0, payload_len=134, next_hdr=6
[<module>:30:{n:5}][print_tcp:75] TCP, 2001:5c0:1000:a:8000:0:82d8:262d -> 2404:6800:4006:806::1016, 56258 -> 443, seq=2290529203, ack=1115370550
[<module>:30:{n:5}][print_tcp:78]          flags=18 (PA), window=257, checksum=2c9c, urg_ptr=0
[<module>:30:{n:5}][print_tcp:85][print_data:32]  
[<module>:30:{n:5}][print_tcp:85]          payload: 17 03 03 00 6d 00 00 00   00 00 00 00 04 0e d7 8d   79 b3 ac 00 e9 3e 11 df   87 72 bf 75 2f 2c 6b 6a
[<module>:30:{n:5}][print_tcp:85][print_data:37]              0e 57 86 77 25 8b 1a cf   44 a3 5c 62 08 f3 80 fd   83 8d 42 fd 69 ed fb 8a   cd 1f 36 81 92 a0 62 af
[<module>:24]     6: 
[<module>:25:{n:6}][print_ip6:54] 2404:6800:4006:806::1016 -> 2001:5c0:1000:a:8000:0:82d8:262d, proto=6, tclass=0,
[<module>:25:{n:6}][print_ip6:56]             ttl=51, hlen=None, plen=None flow_label=0, payload_len=20, next_hdr=6
[<module>:30:{n:6}][print_tcp:75] TCP, 2404:6800:4006:806::1016 -> 2001:5c0:1000:a:8000:0:82d8:262d, 443 -> 56258, seq=1115370550, ack=2290526720
[<module>:30:{n:6}][print_tcp:78]          flags=10 (A), window=418, checksum=e484, urg_ptr=0
[<module>:30:{n:6}][print_tcp:82]          no payload
[<module>:24]     7: 
[<module>:25:{n:7}][print_ip6:54] 2404:6800:4006:806::1016 -> 2001:5c0:1000:a:8000:0:82d8:262d, proto=6, tclass=0,
[<module>:25:{n:7}][print_ip6:56]             ttl=51, hlen=None, plen=None flow_label=0, payload_len=32, next_hdr=6
[<module>:30:{n:7}][print_tcp:75] TCP, 2404:6800:4006:806::1016 -> 2001:5c0:1000:a:8000:0:82d8:262d, 443 -> 56258, seq=1115370550, ack=2290526720
[<module>:30:{n:7}][print_tcp:78]          flags=10 (A), window=418, checksum=3624, urg_ptr=0
[<module>:30:{n:7}][print_tcp:82]          no payload
[<module>:24]     8: 
[<module>:25:{n:8}][print_ip6:54] 2404:6800:4006:806::1016 -> 2001:5c0:1000:a:8000:0:82d8:262d, proto=6, tclass=0,
[<module>:25:{n:8}][print_ip6:56]             ttl=51, hlen=None, plen=None flow_label=0, payload_len=20, next_hdr=6
[<module>:30:{n:8}][print_tcp:75] TCP, 2404:6800:4006:806::1016 -> 2001:5c0:1000:a:8000:0:82d8:262d, 443 -> 56258, seq=1115370550, ack=2290529203
[<module>:30:{n:8}][print_tcp:78]          flags=10 (A), window=495, checksum=da84, urg_ptr=0
[<module>:30:{n:8}][print_tcp:82]          no payload
[<module>:24]     9: 
[<module>:25:{n:9}][print_ip6:54] 2404:6800:4006:806::1016 -> 2001:5c0:1000:a:8000:0:82d8:262d, proto=6, tclass=0,
[<module>:25:{n:9}][print_ip6:56]             ttl=51, hlen=None, plen=None flow_label=0, payload_len=20, next_hdr=6
[<module>:30:{n:9}][print_tcp:75] TCP, 2404:6800:4006:806::1016 -> 2001:5c0:1000:a:8000:0:82d8:262d, 443 -> 56258, seq=1115370550, ack=2290529317
[<module>:30:{n:9}][print_tcp:78]          flags=10 (A), window=495, checksum=da12, urg_ptr=0
[<module>:30:{n:9}][print_tcp:82]          no payload
[<module>:24]    10: 
[<module>:25:{n:10}][print_ip6:54] 2404:6800:4006:806::1016 -> 2001:5c0:1000:a:8000:0:82d8:262d, proto=6, tclass=0,
[<module>:25:{n:10}][print_ip6:56]             ttl=51, hlen=None, plen=None flow_label=0, payload_len=87, next_hdr=6
[<module>:30:{n:10}][print_tcp:75] TCP, 2404:6800:4006:806::1016 -> 2001:5c0:1000:a:8000:0:82d8:262d, 443 -> 56258, seq=1115370550, ack=2290529317
[<module>:30:{n:10}][print_tcp:78]          flags=18 (PA), window=495, checksum=2f74, urg_ptr=0
[<module>:30:{n:10}][print_tcp:85][print_data:32]  
[<module>:30:{n:10}][print_tcp:85]          payload: 17 03 03 00 3e 00 00 00   00 00 00 00 05 ce aa 90   22 b4 e6 fd 90 f4 be dc   1f 3c cf 71 c6 4b 9c c7
[<module>:30:{n:10}][print_tcp:85][print_data:37]              08 61 a6 a7 4f 98 e8 e3   24 c2 35 10 70 a8 f6 a5   3b 20 63 35 78 91 8c 26   95 9a 77 42 94 4e 62 59
[<module>:24]    11: 
[<module>:25:{n:11}][print_ip6:54] 2404:6800:4006:806::1016 -> 2001:5c0:1000:a:8000:0:82d8:262d, proto=6, tclass=0,
[<module>:25:{n:11}][print_ip6:56]             ttl=51, hlen=None, plen=None flow_label=0, payload_len=67, next_hdr=6
[<module>:30:{n:11}][print_tcp:75] TCP, 2404:6800:4006:806::1016 -> 2001:5c0:1000:a:8000:0:82d8:262d, 443 -> 56258, seq=1115370617, ack=2290529317
[<module>:30:{n:11}][print_tcp:78]          flags=18 (PA), window=495, checksum=4827, urg_ptr=0
[<module>:30:{n:11}][print_tcp:85][print_data:32]  
[<module>:30:{n:11}][print_tcp:85]          payload: 17 03 03 00 2a 00 00 00   00 00 00 00 06 28 5e 4e   d0 ba 19 55 c0 36 33 88   18 51 ae c9 a0 07 ed ea
[<module>:30:{n:11}][print_tcp:85][print_data:37]              8a e6 dd c9 ed 47 9a d9   15 29 d1 b5 46 6a 98
[<module>:24]    12: 
[<module>:25:{n:12}][print_ip6:54] 2001:5c0:1000:a:8000:0:82d8:262d -> 2404:6800:4006:806::1016, proto=6, tclass=0,
[<module>:25:{n:12}][print_ip6:56]             ttl=128, hlen=None, plen=None flow_label=0, payload_len=20, next_hdr=6
[<module>:30:{n:12}][print_tcp:75] TCP, 2001:5c0:1000:a:8000:0:82d8:262d -> 2404:6800:4006:806::1016, 56258 -> 443, seq=2290529317, ack=1115370664
[<module>:30:{n:12}][print_tcp:78]          flags=10 (A), window=256, checksum=da8f, urg_ptr=0
[<module>:30:{n:12}][print_tcp:82]          no payload
[<module>:24]    13: 
[<module>:25:{n:13}][print_ip6:54] 2404:6800:4006:806::1016 -> 2001:5c0:1000:a:8000:0:82d8:262d, proto=6, tclass=0,
[<module>:25:{n:13}][print_ip6:56]             ttl=51, hlen=None, plen=None flow_label=0, payload_len=81, next_hdr=6
[<module>:30:{n:13}][print_tcp:75] TCP, 2404:6800:4006:806::1016 -> 2001:5c0:1000:a:8000:0:82d8:262d, 443 -> 56258, seq=1115370664, ack=2290529317
[<module>:30:{n:13}][print_tcp:78]          flags=18 (PA), window=495, checksum=a4ca, urg_ptr=0
[<module>:30:{n:13}][print_tcp:85][print_data:32]  
[<module>:30:{n:13}][print_tcp:85]          payload: 17 03 03 00 38 00 00 00   00 00 00 00 07 59 bd 96   09 bc c8 9d 9a 27 7d 7c   7c 4d ac c3 cd 96 a3 0a
[<module>:30:{n:13}][print_tcp:85][print_data:37]              3f 30 b5 59 fa ac ba b6   e2 e0 a8 f2 e3 b3 fa 24   3b ca 30 9d fc 7b bb 4f   57 52 48 cd c2
[<module>:24]    14: 
[<module>:25:{n:14}][print_ip6:54] 2404:6800:4006:806::1016 -> 2001:5c0:1000:a:8000:0:82d8:262d, proto=6, tclass=0,
[<module>:25:{n:14}][print_ip6:56]             ttl=51, hlen=None, plen=None flow_label=0, payload_len=61, next_hdr=6
[<module>:30:{n:14}][print_tcp:75] TCP, 2404:6800:4006:806::1016 -> 2001:5c0:1000:a:8000:0:82d8:262d, 443 -> 56258, seq=1115370725, ack=2290529317
[<module>:30:{n:14}][print_tcp:78]          flags=18 (PA), window=495, checksum=9eae, urg_ptr=0
[<module>:30:{n:14}][print_tcp:85][print_data:32]  
[<module>:30:{n:14}][print_tcp:85]          payload: 17 03 03 00 24 00 00 00   00 00 00 00 08 47 a2 97   5b 51 76 51 f7 5b 7e 3a   87 ab 8d 8e e0 e9 b0 43
[<module>:30:{n:14}][print_tcp:85][print_data:37]              c5 d9 20 6f 73 de 06 da   03
[<module>:24]    15: 
[<module>:25:{n:15}][print_ip6:54] 2001:5c0:1000:a:8000:0:82d8:262d -> 2404:6800:4006:806::1016, proto=6, tclass=0,
[<module>:25:{n:15}][print_ip6:56]             ttl=128, hlen=None, plen=None flow_label=0, payload_len=20, next_hdr=6
[<module>:30:{n:15}][print_tcp:75] TCP, 2001:5c0:1000:a:8000:0:82d8:262d -> 2404:6800:4006:806::1016, 56258 -> 443, seq=2290529317, ack=1115370766
[<module>:30:{n:15}][print_tcp:78]          flags=10 (A), window=256, checksum=da29, urg_ptr=0
[<module>:30:{n:15}][print_tcp:82]          no payload
[<module>:24]    16: 
[<module>:25:{n:16}][print_ip6:54] 2001:5c0:1000:a:8000:0:82d8:262d -> 2404:6800:4006:806::1016, proto=6, tclass=0,
[<module>:25:{n:16}][print_ip6:56]             ttl=128, hlen=None, plen=None flow_label=0, payload_len=61, next_hdr=6
[<module>:30:{n:16}][print_tcp:75] TCP, 2001:5c0:1000:a:8000:0:82d8:262d -> 2404:6800:4006:806::1016, 56258 -> 443, seq=2290529317, ack=1115370766
[<module>:30:{n:16}][print_tcp:78]          flags=18 (PA), window=256, checksum=bf9a, urg_ptr=0
[<module>:30:{n:16}][print_tcp:85][print_data:32]  
[<module>:30:{n:16}][print_tcp:85]          payload: 17 03 03 00 24 00 00 00   00 00 00 00 05 81 99 05   fc 56 ff cc a4 a8 be 65   1a 24 d1 97 ac 59 91 6d
[<module>:30:{n:16}][print_tcp:85][print_data:37]              b9 02 b3 89 38 e4 3f ad   d0
[<module>:24]    17: 
[<module>:25:{n:17}][print_ip6:54] 2404:6800:4006:806::1016 -> 2001:5c0:1000:a:8000:0:82d8:262d, proto=6, tclass=0,
[<module>:25:{n:17}][print_ip6:56]             ttl=51, hlen=None, plen=None flow_label=0, payload_len=20, next_hdr=6
[<module>:30:{n:17}][print_tcp:75] TCP, 2404:6800:4006:806::1016 -> 2001:5c0:1000:a:8000:0:82d8:262d, 443 -> 56258, seq=1115370766, ack=2290529358
[<module>:30:{n:17}][print_tcp:78]          flags=10 (A), window=495, checksum=d911, urg_ptr=0
[<module>:30:{n:17}][print_tcp:82]          no payload
[<module>:24]    18: 
[<module>:25:{n:18}][print_ip6:54] 2001:5c0:1000:a:8000:0:82d8:262d -> 2404:6800:4006:804::1007, proto=58, tclass=0,
[<module>:25:{n:18}][print_ip6:56]             ttl=128, hlen=None, plen=None flow_label=0, payload_len=40, next_hdr=58
[<module>:24]    19: 
[<module>:25:{n:19}][print_ip6:54] 2404:6800:4006:804::1007 -> 2001:5c0:1000:a:8000:0:82d8:262d, proto=58, tclass=0,
[<module>:25:{n:19}][print_ip6:56]             ttl=51, hlen=None, plen=None flow_label=0, payload_len=40, next_hdr=58
[<module>:24]    20: 
[<module>:25:{n:20}][print_ip6:54] 2001:5c0:1000:a:8000:0:82d8:262d -> 2404:6800:4006:805::1008, proto=6, tclass=0,
[<module>:25:{n:20}][print_ip6:56]             ttl=128, hlen=None, plen=None flow_label=0, payload_len=21, next_hdr=6
[<module>:30:{n:20}][print_tcp:75] TCP, 2001:5c0:1000:a:8000:0:82d8:262d -> 2404:6800:4006:805::1008, 56278 -> 80, seq=3999506765, ack=52310676
[<module>:30:{n:20}][print_tcp:78]          flags=10 (A), window=254, checksum=ca62, urg_ptr=0
[<module>:30:{n:20}][print_tcp:85][print_data:32]  
[<module>:30:{n:20}][print_tcp:85]          payload: 00
