[<module>:14] 1.2.3.4 -> 1,  254527795
[<module>:14] 1.2.3.5 -> 2,  1949026611
[<module>:14] 1.2.4.4 -> 3,  76728627
[<module>:14] 1.3.3.4 -> 4,  161625651
[<module>:14] 2.2.3.4 -> 5,  254625418
[<module>:17] ip01 =            192.168.10.1/16
[<module>:18] ip01.complement = 63.87.245.254/16
[<module>:19] ip01.width      = 15
[<module>:20] ip01.is_rfc1918 = True
[test_ip:26] --- trying 192.168.0.2
[test_ip:28]    slash: 192.168.0.0/16.is_prefix(192.168.0.2) -> True
[test_ip:30] 192.168.0.2 -> True
[test_ip:26] --- trying 192.168.1.3/32
[test_ip:28]    slash: 192.168.0.0/16.is_prefix(192.168.1.3/32) -> True
[test_ip:30] 192.168.1.3/32 -> True
[test_ip:26] --- trying 130.216.12.34
[test_ip:28]    slash: 192.168.0.0/16.is_prefix(130.216.12.34) -> False
[test_ip:30] 130.216.12.34 -> False
[test_ip:26] --- trying 130.216.56.78/32
[test_ip:28]    slash: 192.168.0.0/16.is_prefix(130.216.56.78/32) -> False
[test_ip:30] 130.216.56.78/32 -> False
[<module>:46] Exception caught
