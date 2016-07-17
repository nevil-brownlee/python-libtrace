[get_example_trace:23]fn = icmp-sample.pcap

[<module>:24]     1: 
[<module>:25:{n:1}][print_icmp:99]            ICMP, type=0, code=0, checksum=e2a2,  wlen=64, clen=60, 2013-11-25 11:19:28.270644
[<module>:25:{n:1}][print_icmp:109]            Echo reply,   ident=1d5c, sequence=1
[<module>:25:{n:1}][print_icmp:130][print_data:32]              Echo  00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00
 
[<module>:24]     2: 
[<module>:25:{n:2}][print_icmp:99]            ICMP, type=3, code=3, checksum=4b69,  wlen=524, clen=520, 2013-11-25 11:19:28.277832
[<module>:25:{n:2}][print_icmp:113]            Destination unreachable, [print_icmp_ip:94] proto=1, TTL=63, pkt_len=506
[<module>:25:{n:2}][print_icmp:130][print_data:32]              IP    45 00 01 de 86 28 00 00   3d 11 a9 56 73 92 51 d2   82 d8 04 54 b3 be b3 be   01 ca c9 f7 7b 54 03 00
[<module>:25:{n:2}][print_icmp:130][print_data:37]                  00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
 
[<module>:24]     3: 
[<module>:25:{n:3}][print_icmp:99]            ICMP, type=8, code=0, checksum=2716,  wlen=1016, clen=1012, 2013-11-25 11:19:28.280426
[<module>:25:{n:3}][print_icmp:109]            Echo request, ident=0201, sequence=57996
[<module>:25:{n:3}][print_icmp:130][print_data:32]              Echo  04 ac 35 54 70 7b 92 52   e6 03 66 23 74 70 73 66   77 64 70 69 6e 67 01 01   af ec 8d 6e 88 8c 72 66
[<module>:25:{n:3}][print_icmp:130][print_data:37]                  99 8d e1 a3 02 d3 9b d3   c7 b8 15 f7 fb 95 52 e0   69 e3 ec 0f 34 35 36 37   38 39 3a 3b 3c 3d 3e 3f
 
[<module>:24]     4: 
[<module>:25:{n:4}][print_icmp:99]            ICMP, type=0, code=0, checksum=2f16,  wlen=1016, clen=1012, 2013-11-25 11:19:28.280776
[<module>:25:{n:4}][print_icmp:109]            Echo reply,   ident=0201, sequence=57996
[<module>:25:{n:4}][print_icmp:130][print_data:32]              Echo  04 ac 35 54 70 7b 92 52   e6 03 66 23 74 70 73 66   77 64 70 69 6e 67 01 01   af ec 8d 6e 88 8c 72 66
[<module>:25:{n:4}][print_icmp:130][print_data:37]                  99 8d e1 a3 02 d3 9b d3   c7 b8 15 f7 fb 95 52 e0   69 e3 ec 0f 34 35 36 37   38 39 3a 3b 3c 3d 3e 3f
 
[<module>:24]     5: 
[<module>:25:{n:5}][print_icmp:99]            ICMP, type=8, code=0, checksum=d196,  wlen=1018, clen=1014, 2013-11-25 11:19:28.281336
[<module>:25:{n:5}][print_icmp:109]            Echo request, ident=904b, sequence=38031
[<module>:25:{n:5}][print_icmp:130][print_data:32]              Echo  70 7b 92 52 5f 44 04 00   08 09 0a 0b 0c 0d 0e 0f   10 11 12 13 14 15 16 17   18 19 1a 1b 1c 1d 1e 1f
[<module>:25:{n:5}][print_icmp:130][print_data:37]                  20 21 22 23 24 25 26 27   28 29 2a 2b 2c 2d 2e 2f   30 31 32 33 34 35 36 37   38 39 3a 3b 3c 3d 3e 3f
 
[<module>:24]     6: 
[<module>:25:{n:6}][print_icmp:99]            ICMP, type=0, code=0, checksum=d996,  wlen=1018, clen=1014, 2013-11-25 11:19:28.282222
[<module>:25:{n:6}][print_icmp:109]            Echo reply,   ident=904b, sequence=38031
[<module>:25:{n:6}][print_icmp:130][print_data:32]              Echo  70 7b 92 52 5f 44 04 00   08 09 0a 0b 0c 0d 0e 0f   10 11 12 13 14 15 16 17   18 19 1a 1b 1c 1d 1e 1f
[<module>:25:{n:6}][print_icmp:130][print_data:37]                  20 21 22 23 24 25 26 27   28 29 2a 2b 2c 2d 2e 2f   30 31 32 33 34 35 36 37   38 39 3a 3b 3c 3d 3e 3f
 
[<module>:24]     7: 
[<module>:25:{n:7}][print_icmp:99]            ICMP, type=8, code=0, checksum=80b0,  wlen=102, clen=98, 2013-11-25 11:19:28.282623
[<module>:25:{n:7}][print_icmp:109]            Echo request, ident=69cb, sequence=0
[<module>:25:{n:7}][print_icmp:130][print_data:32]              Echo  78 88 92 52 0a a6 0d 00   08 09 0a 0b 0c 0d 0e 0f   10 11 12 13 14 15 16 17   18 19 1a 1b 1c 1d 1e 1f
[<module>:25:{n:7}][print_icmp:130][print_data:37]                  20 21 22 23 24 25 26 27   28 29 2a 2b 2c 2d 2e 2f   30 31 32 33 34 35 36 37
 
[<module>:24]     8: 
[<module>:25:{n:8}][print_icmp:99]            ICMP, type=0, code=0, checksum=88b0,  wlen=102, clen=98, 2013-11-25 11:19:28.283521
[<module>:25:{n:8}][print_icmp:109]            Echo reply,   ident=69cb, sequence=0
[<module>:25:{n:8}][print_icmp:130][print_data:32]              Echo  78 88 92 52 0a a6 0d 00   08 09 0a 0b 0c 0d 0e 0f   10 11 12 13 14 15 16 17   18 19 1a 1b 1c 1d 1e 1f
[<module>:25:{n:8}][print_icmp:130][print_data:37]                  20 21 22 23 24 25 26 27   28 29 2a 2b 2c 2d 2e 2f   30 31 32 33 34 35 36 37
 
[<module>:24]     9: 
[<module>:25:{n:9}][print_icmp:99]            ICMP, type=8, code=0, checksum=6299,  wlen=1016, clen=1012, 2013-11-25 11:19:28.288414
[<module>:25:{n:9}][print_icmp:109]            Echo request, ident=7e54, sequence=28967
[<module>:25:{n:9}][print_icmp:130][print_data:32]              Echo  70 7b 92 52 cf 6c 03 00   08 09 0a 0b 0c 0d 0e 0f   10 11 12 13 14 15 16 17   18 19 1a 1b 1c 1d 1e 1f
[<module>:25:{n:9}][print_icmp:130][print_data:37]                  20 21 22 23 24 25 26 27   28 29 2a 2b 2c 2d 2e 2f   30 31 32 33 34 35 36 37   38 39 3a 3b 3c 3d 3e 3f
 
[<module>:24]    10: 
[<module>:25:{n:10}][print_icmp:99]            ICMP, type=11, code=0, checksum=e062,  wlen=186, clen=182, 2013-11-25 11:19:28.289715
[<module>:25:{n:10}]            Time exceeded, [print_icmp_ip:94] proto=1, TTL=56, pkt_len=168
[<module>:25:{n:10}][print_icmp:130][print_data:32]              IP    45 f4 00 28 23 f5 00 00   01 06 a9 7f 82 d8 23 3c   73 57 d1 fc 93 8c 00 50   e1 a9 59 29 00 00 00 00
[<module>:25:{n:10}][print_icmp:130][print_data:37]                  50 10 0a 8c eb 30 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
 
[<module>:24]    11: 
[<module>:25:{n:11}][print_icmp:99]            ICMP, type=3, code=3, checksum=68b2,  wlen=234, clen=230, 2013-11-25 11:19:28.303189
[<module>:25:{n:11}][print_icmp:113]            Destination unreachable, [print_icmp_ip:94] proto=1, TTL=124, pkt_len=216
[<module>:25:{n:11}][print_icmp:130][print_data:32]              IP    45 00 00 bc e3 b0 00 00   3d 11 2e 85 ac 18 37 48   82 d8 04 c3 d2 b2 00 a1   00 a8 73 cf 30 81 9d 02
[<module>:25:{n:11}][print_icmp:130][print_data:37]                  01 00 04 06 70 75 62 6c   69 63 a1 81 8f 02 04 40   93 a8 4e 02 01 00 02 01   00 30 81 80 30 0e 06 0a
 
[<module>:24]    12: 
[<module>:25:{n:12}][print_icmp:99]            ICMP, type=11, code=0, checksum=f4ff,  wlen=114, clen=110, 2013-11-25 11:19:28.313824
[<module>:25:{n:12}]            Time exceeded, [print_icmp_ip:94] proto=1, TTL=247, pkt_len=96
[<module>:25:{n:12}][print_icmp:130][print_data:32]              IP    45 40 00 1e 00 01 00 00   01 01 48 e1 82 d8 01 17   ca a9 22 25 08 00 e8 f9   c8 9f 0a 01 3c 65 00 00
[<module>:25:{n:12}][print_icmp:130][print_data:37]                  00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00
 
[<module>:24]    13: 
[<module>:25:{n:13}][print_icmp:99]            ICMP, type=3, code=3, checksum=a144,  wlen=74, clen=70, 2013-11-25 11:19:28.331892
[<module>:25:{n:13}][print_icmp:113]            Destination unreachable, [print_icmp_ip:94] proto=1, TTL=49, pkt_len=56
[<module>:25:{n:13}][print_icmp:130][print_data:32]              IP    45 00 00 3a 02 a1 00 00   67 11 d8 5f 82 d8 1e 76   92 fb 44 69 fc dd 80 54   00 26 de 5f
 
[<module>:24]    14: 
[<module>:25:{n:14}][print_icmp:99]            ICMP, type=3, code=3, checksum=a144,  wlen=74, clen=70, 2013-11-25 11:19:28.331893
[<module>:25:{n:14}][print_icmp:113]            Destination unreachable, [print_icmp_ip:94] proto=1, TTL=48, pkt_len=56
[<module>:25:{n:14}][print_icmp:130][print_data:32]              IP    45 00 00 3a 02 a1 00 00   67 11 d8 5f 82 d8 1e 76   92 fb 44 69 fc dd 80 54   00 26 de 5f
 
[<module>:24]    15: 
[<module>:25:{n:15}][print_icmp:99]            ICMP, type=11, code=0, checksum=32c1,  wlen=74, clen=70, 2013-11-25 11:19:28.349416
[<module>:25:{n:15}]            Time exceeded, [print_icmp_ip:94] proto=1, TTL=255, pkt_len=56
[<module>:25:{n:15}][print_icmp:130][print_data:32]              IP    45 00 00 20 48 98 00 00   01 11 ea 2f a5 d7 c0 07   82 d8 9e 4e 2c a6 82 9b   00 0c 12 f1
 
[<module>:24]    16: 
[<module>:25:{n:16}][print_icmp:99]            ICMP, type=11, code=0, checksum=8746,  wlen=74, clen=70, 2013-11-25 11:19:28.357604
[<module>:25:{n:16}]            Time exceeded, [print_icmp_ip:94] proto=1, TTL=248, pkt_len=56
[<module>:25:{n:16}][print_icmp:130][print_data:32]              IP    45 00 00 3c 75 28 00 00   01 11 a7 81 82 d8 01 17   8b 13 8e 05 bc 11 82 b5   00 28 2e ca
 
[<module>:24]    17: 
[<module>:25:{n:17}][print_icmp:99]            ICMP, type=5, code=1, checksum=796e,  wlen=95, clen=91, 2013-11-25 11:19:32.800035
[<module>:25:{n:17}]            Redirect, gateway=172.25.33.254, [print_icmp_ip:94] proto=1, TTL=53, pkt_len=77
[<module>:25:{n:17}][print_icmp:130][print_data:32]              IP    45 00 00 31 00 00 40 00   36 11 f8 63 82 d8 01 17   29 cb 9e 9e e3 20 00 35   00 1d 1f db 3c 58 01 00
[<module>:25:{n:17}][print_icmp:130][print_data:37]                  00 01 00 00 00 00 00 00   03 63 6f 6d 00 00 ff 00   01
 
[<module>:24]    18: 
[<module>:25:{n:18}][print_icmp:99]            ICMP, type=4, code=0, checksum=43fe,  wlen=74, clen=70, 2013-11-25 11:19:43.031877
[<module>:25:{n:18}]            Source quench, [print_icmp_ip:94] proto=1, TTL=235, pkt_len=56
[<module>:25:{n:18}][print_icmp:130][print_data:32]              IP    45 00 00 1e 37 9e 00 00   30 11 ef 50 82 d8 1e 76   c0 a8 01 ea 5a 10 04 4c   00 0a 59 9b
 
[<module>:24]    19: 
[<module>:25:{n:19}][print_icmp:99]            ICMP, type=4, code=0, checksum=43fe,  wlen=74, clen=70, 2013-11-25 11:19:43.031923
[<module>:25:{n:19}]            Source quench, [print_icmp_ip:94] proto=1, TTL=234, pkt_len=56
[<module>:25:{n:19}][print_icmp:130][print_data:32]              IP    45 00 00 1e 37 9e 00 00   30 11 ef 50 82 d8 1e 76   c0 a8 01 ea 5a 10 04 4c   00 0a 59 9b
 
[<module>:34] 19 packets examined

