[get_example_trace:23]fn = anon-v4.pcap

[<module>:23:{n:8}] n=  8, kind=packet, type=Layer2, size=68, linktype=2, ethertype=0800
[<module>:25:{n:8}][print_data:32]  Packet:       01 00 5e 00 00 0d 00 d0   2b 4b 75 1b 08 00 45 c0   00 36 98 1a 00 00 01 67   4d 73 cf d1 04 01 fe d8 
[<module>:25:{n:8}][print_data:37]              00 69 20 00 73 1a 00 01   00 02 00 69 00 14 00 04   17 68 53 c8 00 13 00 04   00 00 00 01 00 15 00 04
[<module>:26:{n:8}]                  == kind=packet, type=Packet
[<module>:29:{n:8}][print_data:32]  L2 before:    01 00 5e 00 00 0d 00 d0   2b 4b 75 1b 08 00 45 c0   00 36 98 1a 00 00 01 67   4d 73 cf d1 04 01 fe d8 
[<module>:29:{n:8}][print_data:37]              00 69 20 00 73 1a 00 01   00 02 00 69 00 14 00 04   17 68 53 c8 00 13 00 04   00 00 00 01 00 15 00 04
[<module>:33:{n:8}][print_data:32]  L2 after:     55 66 77 00 00 0d 00 d0   2b 4b 75 1b 08 00 45 c0   00 36 98 1a 00 00 01 67   4d 73 cf d1 04 01 fe d8 
[<module>:33:{n:8}][print_data:37]              00 69 20 00 73 1a 00 01   00 02 00 69 00 14 00 04   17 68 53 c8 00 13 00 04   00 00 00 01 00 15 00 04
[<module>:34:{n:8}]                  == kind=packet, type=Layer2
[<module>:37:{n:8}][print_data:32]  Layer3:       45 c0 00 36 98 1a 00 00   01 67 4d 73 cf d1 04 01   fe d8 00 69 20 00 73 1a   00 01 00 02 00 69 00 14 
[<module>:37:{n:8}][print_data:37]              00 04 17 68 53 c8 00 13   00 04 00 00 00 01 00 15   00 04 01 00 00 00
[<module>:38:{n:8}]                  == kind=packet, type=Layer3
[<module>:41:{n:8}][print_data:32]  Transport:    20 00 73 1a 00 01 00 02   00 69 00 14 00 04 17 68   53 c8 00 13 00 04 00 00   00 01 00 15 00 04 01 00 
[<module>:41:{n:8}][print_data:37]              00 00
[<module>:43:{n:8}]                  == kind=packet, type=Transport, proto=103
[<module>:46:{n:8}][print_data:32]  IP:           45 c0 00 36 98 1a 00 00   01 67 4d 73 cf d1 04 01   fe d8 00 69 20 00 73 1a   00 01 00 02 00 69 00 14 
[<module>:46:{n:8}][print_data:37]              00 04 17 68 53 c8 00 13   00 04 00 00 00 01 00 15   00 04 01 00 00 00
[<module>:48:{n:8}]                  == kind=packet, type=IP, ip.proto=103
 
[<module>:23:{n:9}] n=  9, kind=packet, type=Layer2, size=74, linktype=2, ethertype=0800
[<module>:25:{n:9}][print_data:32]  Packet:       00 14 22 7b f8 4d 00 11   25 17 cc 4f 08 00 45 00   00 3c 84 84 40 00 40 11   0e 0c cf d1 04 2f cf d1 
[<module>:25:{n:9}][print_data:37]              04 4f 81 96 00 35 00 28   e3 c5 b7 ca 01 00 00 01   00 00 00 00 00 00 03 77   77 77 06 67 6f 6f 67 6c
[<module>:26:{n:9}]                  == kind=packet, type=Packet
[<module>:29:{n:9}][print_data:32]  L2 before:    00 14 22 7b f8 4d 00 11   25 17 cc 4f 08 00 45 00   00 3c 84 84 40 00 40 11   0e 0c cf d1 04 2f cf d1 
[<module>:29:{n:9}][print_data:37]              04 4f 81 96 00 35 00 28   e3 c5 b7 ca 01 00 00 01   00 00 00 00 00 00 03 77   77 77 06 67 6f 6f 67 6c
[<module>:33:{n:9}][print_data:32]  L2 after:     55 66 77 7b f8 4d 00 11   25 17 cc 4f 08 00 45 00   00 3c 84 84 40 00 40 11   0e 0c cf d1 04 2f cf d1 
[<module>:33:{n:9}][print_data:37]              04 4f 81 96 00 35 00 28   e3 c5 b7 ca 01 00 00 01   00 00 00 00 00 00 03 77   77 77 06 67 6f 6f 67 6c
[<module>:34:{n:9}]                  == kind=packet, type=Layer2
[<module>:37:{n:9}][print_data:32]  Layer3:       45 00 00 3c 84 84 40 00   40 11 0e 0c cf d1 04 2f   cf d1 04 4f 81 96 00 35   00 28 e3 c5 b7 ca 01 00 
[<module>:37:{n:9}][print_data:37]              00 01 00 00 00 00 00 00   03 77 77 77 06 67 6f 6f   67 6c 65 03 63 6f 6d 00   00 1c 00 01
[<module>:38:{n:9}]                  == kind=packet, type=Layer3
[<module>:41:{n:9}][print_data:32]  Transport:    81 96 00 35 00 28 e3 c5   b7 ca 01 00 00 01 00 00   00 00 00 00 03 77 77 77   06 67 6f 6f 67 6c 65 03 
[<module>:41:{n:9}][print_data:37]              63 6f 6d 00 00 1c 00 01
[<module>:43:{n:9}]                  == kind=packet, type=Transport, proto=17
[<module>:46:{n:9}][print_data:32]  IP:           45 00 00 3c 84 84 40 00   40 11 0e 0c cf d1 04 2f   cf d1 04 4f 81 96 00 35   00 28 e3 c5 b7 ca 01 00 
[<module>:46:{n:9}][print_data:37]              00 01 00 00 00 00 00 00   03 77 77 77 06 67 6f 6f   67 6c 65 03 63 6f 6d 00   00 1c 00 01
[<module>:48:{n:9}]                  == kind=packet, type=IP, ip.proto=17
 
[<module>:23:{n:10}] n= 10, kind=packet, type=Layer2, size=96, linktype=2, ethertype=0800
[<module>:25:{n:10}][print_data:32]  Packet:       00 11 25 17 cc 4f 00 14   22 7b f8 4d 08 00 45 00   00 80 04 95 00 00 40 11   cd b7 cf d1 04 4f cf d1 
[<module>:25:{n:10}][print_data:37]              04 2f 00 35 81 96 00 6c   d1 7e b7 ca 81 80 00 01   00 01 00 01 00 00 03 77   77 77 06 67 6f 6f 67 6c
[<module>:26:{n:10}]                  == kind=packet, type=Packet
[<module>:29:{n:10}][print_data:32]  L2 before:    00 11 25 17 cc 4f 00 14   22 7b f8 4d 08 00 45 00   00 80 04 95 00 00 40 11   cd b7 cf d1 04 4f cf d1 
[<module>:29:{n:10}][print_data:37]              04 2f 00 35 81 96 00 6c   d1 7e b7 ca 81 80 00 01   00 01 00 01 00 00 03 77   77 77 06 67 6f 6f 67 6c
[<module>:33:{n:10}][print_data:32]  L2 after:     55 66 77 17 cc 4f 00 14   22 7b f8 4d 08 00 45 00   00 80 04 95 00 00 40 11   cd b7 cf d1 04 4f cf d1 
[<module>:33:{n:10}][print_data:37]              04 2f 00 35 81 96 00 6c   d1 7e b7 ca 81 80 00 01   00 01 00 01 00 00 03 77   77 77 06 67 6f 6f 67 6c
[<module>:34:{n:10}]                  == kind=packet, type=Layer2
[<module>:37:{n:10}][print_data:32]  Layer3:       45 00 00 80 04 95 00 00   40 11 cd b7 cf d1 04 4f   cf d1 04 2f 00 35 81 96   00 6c d1 7e b7 ca 81 80 
[<module>:37:{n:10}][print_data:37]              00 01 00 01 00 01 00 00   03 77 77 77 06 67 6f 6f   67 6c 65 03 63 6f 6d 00   00 1c 00 01 c0 0c 00 05
[<module>:38:{n:10}]                  == kind=packet, type=Layer3
[<module>:41:{n:10}][print_data:32]  Transport:    00 35 81 96 00 6c d1 7e   b7 ca 81 80 00 01 00 01   00 01 00 00 03 77 77 77   06 67 6f 6f 67 6c 65 03 
[<module>:41:{n:10}][print_data:37]              63 6f 6d 00 00 1c 00 01   c0 0c 00 05 00 01 00 04   03 6f 00 08 03 77 77 77   01 6c c0 10 c0 30
[<module>:43:{n:10}]                  == kind=packet, type=Transport, proto=17
[<module>:46:{n:10}][print_data:32]  IP:           45 00 00 80 04 95 00 00   40 11 cd b7 cf d1 04 4f   cf d1 04 2f 00 35 81 96   00 6c d1 7e b7 ca 81 80 
[<module>:46:{n:10}][print_data:37]              00 01 00 01 00 01 00 00   03 77 77 77 06 67 6f 6f   67 6c 65 03 63 6f 6d 00   00 1c 00 01 c0 0c 00 05
[<module>:48:{n:10}]                  == kind=packet, type=IP, ip.proto=17
 
[<module>:53] 11 packets in trace

