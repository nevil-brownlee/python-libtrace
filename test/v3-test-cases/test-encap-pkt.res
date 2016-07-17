[get_example_trace:23]fn = anon-v4.pcap

[<module>:25]     8:
[<module>:26:{n:8}][print_ip:45] 207.209.4.1 -> 254.216.0.105, proto=103, tclass=c0,
[<module>:26:{n:8}][print_ip:47]             ttl=1, hlen=5, plen=54,  mf=False, frag_offset=0, ident=981a
[<module>:45:{n:8}] Unknown: proto=103
 
[<module>:25]     9:
[<module>:26:{n:9}][print_ip:45] 207.209.4.47 -> 207.209.4.79, proto=17, tclass=0,
[<module>:26:{n:9}][print_ip:47]             ttl=64, hlen=5, plen=60,  mf=False, frag_offset=0, ident=8484
[<module>:36:{n:9}][print_udp:88] UDP, src_port=33174, dest_port=53, len=40, checksum=e3c5
 
[<module>:25]    10:
[<module>:26:{n:10}][print_ip:45] 207.209.4.79 -> 207.209.4.47, proto=17, tclass=0,
[<module>:26:{n:10}][print_ip:47]             ttl=64, hlen=5, plen=128,  mf=False, frag_offset=0, ident=0495
[<module>:36:{n:10}][print_udp:88] UDP, src_port=53, dest_port=33174, len=108, checksum=d17e
 
[<module>:25]    11:
[<module>:26:{n:11}][print_ip:45] 207.209.4.47 -> 207.209.4.79, proto=17, tclass=0,
[<module>:26:{n:11}][print_ip:47]             ttl=64, hlen=5, plen=60,  mf=False, frag_offset=0, ident=8487
[<module>:36:{n:11}][print_udp:88] UDP, src_port=33174, dest_port=53, len=40, checksum=e3c5
 
[<module>:25]    12:
[<module>:26:{n:12}][print_ip:45] 207.209.4.79 -> 207.209.4.47, proto=17, tclass=0,
[<module>:26:{n:12}][print_ip:47]             ttl=64, hlen=5, plen=240,  mf=False, frag_offset=0, ident=049a
[<module>:36:{n:12}][print_udp:88] UDP, src_port=53, dest_port=33174, len=220, checksum=b201
 
[<module>:25]    13:
[<module>:26:{n:13}][print_ip:45] 207.209.4.47 -> 71.45.40.215, proto=6, tclass=0,
[<module>:26:{n:13}][print_ip:47]             ttl=64, hlen=5, plen=60,  mf=False, frag_offset=0, ident=2e2c
[<module>:32:{n:13}][print_tcp:75] TCP, 207.209.4.47 -> 71.45.40.215, 38760 -> 80, seq=2987567777, ack=0
[<module>:32:{n:13}][print_tcp:78]          flags=02 (S), window=5840, checksum=73f6, urg_ptr=0
[<module>:32:{n:13}][print_tcp:82]          no payload
 
[<module>:25]    14:
[<module>:26:{n:14}][print_ip:45] 207.209.4.47 -> 207.209.4.79, proto=17, tclass=0,
[<module>:26:{n:14}][print_ip:47]             ttl=64, hlen=5, plen=61,  mf=False, frag_offset=0, ident=849b
[<module>:36:{n:14}][print_udp:88] UDP, src_port=33174, dest_port=53, len=41, checksum=e3c6
 
[<module>:25]    15:
[<module>:26:{n:15}][print_ip:45] 71.45.40.215 -> 207.209.4.47, proto=6, tclass=0,
[<module>:26:{n:15}][print_ip:47]             ttl=48, hlen=5, plen=60,  mf=False, frag_offset=0, ident=f296
[<module>:32:{n:15}][print_tcp:75] TCP, 71.45.40.215 -> 207.209.4.47, 80 -> 38760, seq=1823039428, ack=2987567778
[<module>:32:{n:15}][print_tcp:78]          flags=12 (SA), window=5672, checksum=c7f5, urg_ptr=0
[<module>:32:{n:15}][print_tcp:82]          no payload
 
[<module>:25]    16:
[<module>:26:{n:16}][print_ip:45] 207.209.4.47 -> 71.45.40.215, proto=6, tclass=0,
[<module>:26:{n:16}][print_ip:47]             ttl=64, hlen=5, plen=40,  mf=False, frag_offset=0, ident=0000
[<module>:32:{n:16}][print_tcp:75] TCP, 207.209.4.47 -> 71.45.40.215, 38760 -> 80, seq=2987567778, ack=0
[<module>:32:{n:16}][print_tcp:78]          flags=04 (R), window=0, checksum=776e, urg_ptr=0
[<module>:32:{n:16}][print_tcp:82]          no payload
 
[<module>:25]    17:
[<module>:26:{n:17}][print_ip:45] 207.209.4.79 -> 207.209.4.47, proto=17, tclass=0,
[<module>:26:{n:17}][print_ip:47]             ttl=64, hlen=5, plen=125,  mf=False, frag_offset=0, ident=04a1
[<module>:36:{n:17}][print_udp:88] UDP, src_port=53, dest_port=33174, len=105, checksum=4e8b
 
[<module>:25]    18:
[<module>:26:{n:18}][print_ip:45] 207.209.4.47 -> 207.209.4.79, proto=17, tclass=0,
[<module>:26:{n:18}][print_ip:47]             ttl=64, hlen=5, plen=71,  mf=False, frag_offset=0, ident=84be
[<module>:36:{n:18}][print_udp:88] UDP, src_port=33174, dest_port=53, len=51, checksum=e3d0
 
[<module>:25]    19:
[<module>:26:{n:19}][print_ip:45] 207.209.4.79 -> 207.209.4.47, proto=17, tclass=0,
[<module>:26:{n:19}][print_ip:47]             ttl=64, hlen=5, plen=118,  mf=False, frag_offset=0, ident=04a4
[<module>:36:{n:19}][print_udp:88] UDP, src_port=53, dest_port=33174, len=98, checksum=531f
 
[<module>:25]    20:
[<module>:26:{n:20}][print_ip:45] 207.209.4.47 -> 207.209.4.79, proto=17, tclass=0,
[<module>:26:{n:20}][print_ip:47]             ttl=64, hlen=5, plen=61,  mf=False, frag_offset=0, ident=84c3
[<module>:36:{n:20}][print_udp:88] UDP, src_port=33174, dest_port=53, len=41, checksum=e3c6
 
[<module>:25]    21:
[<module>:26:{n:21}][print_ip:45] 207.209.4.79 -> 207.209.4.47, proto=17, tclass=0,
[<module>:26:{n:21}][print_ip:47]             ttl=64, hlen=5, plen=126,  mf=False, frag_offset=0, ident=04bf
[<module>:36:{n:21}][print_udp:88] UDP, src_port=53, dest_port=33174, len=106, checksum=4711
 
[<module>:25]    22:
[<module>:26:{n:22}][print_ip:45] 207.209.4.47 -> 77.126.163.156, proto=6, tclass=0,
[<module>:26:{n:22}][print_ip:47]             ttl=64, hlen=5, plen=60,  mf=False, frag_offset=0, ident=79af
[<module>:32:{n:22}][print_tcp:75] TCP, 207.209.4.47 -> 77.126.163.156, 45316 -> 80, seq=3367435587, ack=0
[<module>:32:{n:22}][print_tcp:78]          flags=02 (S), window=5840, checksum=6f9e, urg_ptr=0
[<module>:32:{n:22}][print_tcp:82]          no payload
 
