[<module>:29]     1: 130.216.207.2 -> 192.31.80.30
[<module>:40]        query, ident=93ed, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           focalspot.com.s6a2.psmtp.com.	  1
[<module>:77] 
[<module>:29]     2: 130.216.191.251 -> 130.216.1.1
[<module>:40]        query, ident=3a74, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           voyager.auckland.ac.nz.	  1
[<module>:77] 
[<module>:29]     3: 130.216.1.1 -> 130.216.191.251
[<module>:40]        response, ident=3a74, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           voyager.auckland.ac.nz.	  1
[<module>:55]        Response list (2 items)
[<module>:58]           voyager.auckland.ac.nz.	1800	CNAME	lyra.auckland.ac.nz.
[<module>:58]           lyra.auckland.ac.nz.	1800	A	130.216.191.98
[<module>:64]        Authority list (5 items)
[<module>:67]           auckland.ac.nz.	1800	NS	dhcp2.tmk.auckland.ac.nz.
[<module>:67]           auckland.ac.nz.	1800	NS	pubsec.domainz.net.nz.
[<module>:67]           auckland.ac.nz.	1800	NS	dns1.auckland.ac.nz.
[<module>:67]           auckland.ac.nz.	1800	NS	dns2.auckland.ac.nz.
[<module>:67]           auckland.ac.nz.	1800	NS	dhcp1.tmk.auckland.ac.nz.
[<module>:73]        Additional list (5 items)
[<module>:76]           dns1.auckland.ac.nz.	1800	A	130.216.1.2
[<module>:76]           dns2.auckland.ac.nz.	1800	A	130.216.1.1
[<module>:76]           dhcp1.tmk.auckland.ac.nz.	1800	A	130.216.207.1
[<module>:76]           dhcp2.tmk.auckland.ac.nz.	1800	A	130.216.207.2
[<module>:76]           pubsec.domainz.net.nz.	790	A	202.46.160.4
[<module>:77] 
[<module>:29]     4: 63.247.83.188 -> 130.216.207.1
[<module>:40]        response, ident=91d1, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           www.seeks.co.nz.	  1
[<module>:53]        Response list empty
[<module>:64]        Authority list (7 items)
[<module>:67]           nz.	58143	NS	NS7.DNS.NET.nz.
[<module>:67]           nz.	58143	NS	NS1.DNS.NET.nz.
[<module>:67]           nz.	58143	NS	NS2.DNS.NET.nz.
[<module>:67]           nz.	58143	NS	NS3.DNS.NET.nz.
[<module>:67]           nz.	58143	NS	NS4.DNS.NET.nz.
[<module>:67]           nz.	58143	NS	NS5.DNS.NET.nz.
[<module>:67]           nz.	58143	NS	NS6.DNS.NET.nz.
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]     5: 130.216.207.1 -> 63.247.83.187
[<module>:40]        query, ident=8aed, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           www.seeks.co.nz.	  1
[<module>:77] 
[<module>:29]     6: 130.216.191.251 -> 130.216.1.1
[<module>:40]        query, ident=d5cb, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           45.191.216.130.in-addr.arpa.	 12
[<module>:77] 
[<module>:29]     7: 130.216.1.1 -> 130.216.191.251
[<module>:40]        response, ident=d5cb, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           45.191.216.130.in-addr.arpa.	 12
[<module>:55]        Response list (1 items)
[<module>:58]           45.191.216.130.in-addr.arpa.	1800	PTR	ecafs-bk01.ec.auckland.ac.nz.
[<module>:64]        Authority list (2 items)
[<module>:67]           216.130.in-addr.arpa.	1800	NS	dns2.auckland.ac.nz.
[<module>:67]           216.130.in-addr.arpa.	1800	NS	dns1.auckland.ac.nz.
[<module>:73]        Additional list (2 items)
[<module>:76]           dns1.auckland.ac.nz.	1800	A	130.216.1.2
[<module>:76]           dns2.auckland.ac.nz.	1800	A	130.216.1.1
[<module>:77] 
[<module>:29]     8: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=cdee, opcode=0 (QUERY), rcode=3 (NXDOMAIN)
[<module>:46]        Query list (1 items)
[<module>:48]           granbychamber.com.multi.surbl.org.	  1
[<module>:53]        Response list empty
[<module>:64]        Authority list (1 items)
[<module>:67]           multi.surbl.org.	900	SOA	dev.null. zone.surbl.org. 1206986581 900 900 604800 900
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]     9: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=d7e3, opcode=0 (QUERY), rcode=3 (NXDOMAIN)
[<module>:46]        Query list (1 items)
[<module>:48]           grand-county.com.multi.surbl.org.	  1
[<module>:53]        Response list empty
[<module>:64]        Authority list (1 items)
[<module>:67]           multi.surbl.org.	900	SOA	dev.null. zone.surbl.org. 1206986581 900 900 604800 900
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    10: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=3cf0, opcode=0 (QUERY), rcode=3 (NXDOMAIN)
[<module>:46]        Query list (1 items)
[<module>:48]           grandlakechamber.com.multi.surbl.org.	  1
[<module>:53]        Response list empty
[<module>:64]        Authority list (1 items)
[<module>:67]           multi.surbl.org.	900	SOA	dev.null. zone.surbl.org. 1206986581 900 900 604800 900
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    11: 130.216.207.2 -> 208.17.81.131
[<module>:40]        query, ident=0df2, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           judo.salon.com.	  1
[<module>:77] 
[<module>:29]    12: 130.216.190.242 -> 130.216.1.1
[<module>:40]        query, ident=4ddf, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           switched.com.	 16
[<module>:77] 
[<module>:29]    13: 130.216.1.1 -> 130.216.190.242
[<module>:40]        response, ident=4ddf, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           switched.com.	 16
[<module>:55]        Response list (1 items)
[<module>:58]           switched.com.	293	TXT	"spf2.0/pra ip4:152.163.225.0/24 ip4:205.188.139.0/24 ip4:205.188.144.0/24 ip4:205.188.156.0/23 ip4:205.188.159.0/24 ip4:64.12.136.0/23 ip4:64.12.138.0/24 ip4:64.12.143.99/32 ip4:64.12.143.100/32 ip4:64.12.143.101/32 ptr:mx.aol.com ?all"
[<module>:62]        Authority list empty
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    14: 130.216.191.251 -> 130.216.1.1
[<module>:40]        query, ident=6336, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           104.117.119.82.in-addr.arpa.	 12
[<module>:77] 
[<module>:29]    15: 130.216.191.251 -> 130.216.1.2
[<module>:40]        query, ident=138a, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           host-86-104-78-21.globtel.ro.	  1
[<module>:77] 
[<module>:29]    16: 130.216.1.1 -> 130.216.191.251
[<module>:40]        response, ident=6336, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           104.117.119.82.in-addr.arpa.	 12
[<module>:55]        Response list (1 items)
[<module>:58]           104.117.119.82.in-addr.arpa.	86395	PTR	chello082119117104.chello.sk.
[<module>:64]        Authority list (3 items)
[<module>:67]           117.119.82.in-addr.arpa.	86395	NS	amsns01.chello.com.
[<module>:67]           117.119.82.in-addr.arpa.	86395	NS	ns3.chello.at.
[<module>:67]           117.119.82.in-addr.arpa.	86395	NS	amsns00.chello.com.
[<module>:73]        Additional list (2 items)
[<module>:76]           amsns00.chello.com.	157284	A	212.83.64.141
[<module>:76]           amsns01.chello.com.	155258	A	212.83.64.140
[<module>:77] 
[<module>:29]    17: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=66c4, opcode=0 (QUERY), rcode=3 (NXDOMAIN)
[<module>:46]        Query list (1 items)
[<module>:48]           winterpark-info.com.multi.surbl.org.	  1
[<module>:53]        Response list empty
[<module>:64]        Authority list (1 items)
[<module>:67]           multi.surbl.org.	900	SOA	dev.null. zone.surbl.org. 1206986581 900 900 604800 900
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    18: 130.216.191.251 -> 130.216.1.1
[<module>:40]        query, ident=506d, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           chello082119117104.chello.sk.	  1
[<module>:77] 
[<module>:29]    19: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=355f, opcode=0 (QUERY), rcode=3 (NXDOMAIN)
[<module>:46]        Query list (1 items)
[<module>:48]           cmail2.com.multi.surbl.org.	  1
[<module>:53]        Response list empty
[<module>:64]        Authority list (1 items)
[<module>:67]           multi.surbl.org.	900	SOA	dev.null. zone.surbl.org. 1206986581 900 900 604800 900
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    20: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=f22c, opcode=0 (QUERY), rcode=3 (NXDOMAIN)
[<module>:46]        Query list (1 items)
[<module>:48]           signature-ad.com.multi.surbl.org.	  1
[<module>:53]        Response list empty
[<module>:64]        Authority list (1 items)
[<module>:67]           multi.surbl.org.	900	SOA	dev.null. zone.surbl.org. 1206986581 900 900 604800 900
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    21: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=d12d, opcode=0 (QUERY), rcode=3 (NXDOMAIN)
[<module>:46]        Query list (1 items)
[<module>:48]           kremmlingchamber.com.multi.surbl.org.	  1
[<module>:53]        Response list empty
[<module>:64]        Authority list (1 items)
[<module>:67]           multi.surbl.org.	900	SOA	dev.null. zone.surbl.org. 1206986581 900 900 604800 900
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    22: 202.112.0.53 -> 130.216.207.1
[<module>:40]        query, ident=2c27, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           zeppo.itss.auckland.ac.nz.	  1
[<module>:77] 
[<module>:29]    23: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=45f1, opcode=0 (QUERY), rcode=3 (NXDOMAIN)
[<module>:46]        Query list (1 items)
[<module>:48]           cmail2.com.rhsbl.ahbl.org.	  1
[<module>:53]        Response list empty
[<module>:64]        Authority list (1 items)
[<module>:67]           rhsbl.ahbl.org.	3600	SOA	ns1.ahbl.org. admins.sosdg.org. 1205592813 3600 3600 86400 3600
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    24: 130.216.1.1 -> 130.216.191.251
[<module>:40]        response, ident=4193, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           lifemultimedia.com.	  1
[<module>:55]        Response list (1 items)
[<module>:58]           lifemultimedia.com.	3600	A	67.59.191.136
[<module>:64]        Authority list (3 items)
[<module>:67]           lifemultimedia.com.	3600	NS	ns1.lnhi.net.
[<module>:67]           lifemultimedia.com.	3600	NS	ns2.lnhi.net.
[<module>:67]           lifemultimedia.com.	3600	NS	ns3.lnhi.net.
[<module>:73]        Additional list (3 items)
[<module>:76]           ns1.lnhi.net.	7817	A	209.41.184.100
[<module>:76]           ns2.lnhi.net.	7817	A	65.36.160.56
[<module>:76]           ns3.lnhi.net.	164609	A	65.36.160.18
[<module>:77] 
[<module>:29]    25: 130.216.190.242 -> 130.216.1.1
[<module>:40]        query, ident=5030, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           699.stats.misstrends.com.	  1
[<module>:77] 
[<module>:29]    26: 130.216.1.1 -> 130.216.190.242
[<module>:40]        response, ident=5030, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           699.stats.misstrends.com.	  1
[<module>:55]        Response list (1 items)
[<module>:58]           699.stats.misstrends.com.	39918	A	80.89.112.12
[<module>:64]        Authority list (1 items)
[<module>:67]           stats.misstrends.com.	7683	NS	ns1.e-m.fr.
[<module>:73]        Additional list (1 items)
[<module>:76]           ns1.e-m.fr.	31835	A	80.89.112.1
[<module>:77] 
[<module>:29]    27: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=1fcb, opcode=0 (QUERY), rcode=3 (NXDOMAIN)
[<module>:46]        Query list (1 items)
[<module>:48]           granbychamber.com.multi.uribl.com.	  1
[<module>:53]        Response list empty
[<module>:64]        Authority list (1 items)
[<module>:67]           multi.uribl.com.	300	SOA	uribl.com. dnsadmin.uribl.com. 1206986781 900 450 604800 300
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    28: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=af04, opcode=0 (QUERY), rcode=3 (NXDOMAIN)
[<module>:46]        Query list (1 items)
[<module>:48]           64.222.15.72.sa-accredit.habeas.com.	  1
[<module>:53]        Response list empty
[<module>:64]        Authority list (1 items)
[<module>:67]           sa-accredit.habeas.com.	600	SOA	sa-accredit.habeas.com. root.habeas.com. 1206968448 3600 1200 604800 600
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    29: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=c3e3, opcode=0 (QUERY), rcode=3 (NXDOMAIN)
[<module>:46]        Query list (1 items)
[<module>:48]           grand-county.com.multi.uribl.com.	  1
[<module>:53]        Response list empty
[<module>:64]        Authority list (1 items)
[<module>:67]           multi.uribl.com.	300	SOA	uribl.com. dnsadmin.uribl.com. 1206986781 900 450 604800 300
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    30: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=7783, opcode=0 (QUERY), rcode=3 (NXDOMAIN)
[<module>:46]        Query list (1 items)
[<module>:48]           grandlakechamber.com.multi.uribl.com.	  1
[<module>:53]        Response list empty
[<module>:64]        Authority list (1 items)
[<module>:67]           multi.uribl.com.	300	SOA	uribl.com. dnsadmin.uribl.com. 1206986781 900 450 604800 300
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    31: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=16f3, opcode=0 (QUERY), rcode=3 (NXDOMAIN)
[<module>:46]        Query list (1 items)
[<module>:48]           64.222.15.72.combined.njabl.org.	  1
[<module>:53]        Response list empty
[<module>:64]        Authority list (1 items)
[<module>:67]           combined.njabl.org.	900	SOA	ns1.njabl.org. help.njabl.org. 1206984726 10800 1800 720000 900
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    32: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=11fa, opcode=0 (QUERY), rcode=3 (NXDOMAIN)
[<module>:46]        Query list (1 items)
[<module>:48]           100.110.225.207.combined.njabl.org.	  1
[<module>:53]        Response list empty
[<module>:64]        Authority list (1 items)
[<module>:67]           combined.njabl.org.	900	SOA	ns1.njabl.org. help.njabl.org. 1206984726 10800 1800 720000 900
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    33: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=518d, opcode=0 (QUERY), rcode=3 (NXDOMAIN)
[<module>:46]        Query list (1 items)
[<module>:48]           64.222.15.72.iadb.isipp.com.	  1
[<module>:53]        Response list empty
[<module>:64]        Authority list (1 items)
[<module>:67]           iadb.isipp.com.	7200	SOA	iadb.isipp.com. hostmaster.isipp.com. 2008032801 7200 3600 3600 7200
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    34: 130.216.191.251 -> 130.216.1.1
[<module>:40]        query, ident=ac42, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           bmsupplies.com.	 28
[<module>:77] 
[<module>:29]    35: 130.216.207.1 -> 212.156.4.4
[<module>:40]        query, ident=82a5, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           dsl85-104-62071.ttnet.net.tr.	  1
[<module>:77] 
[<module>:29]    36: 130.216.207.1 -> 208.48.81.43
[<module>:40]        query, ident=7625, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           hardandheavy.de.	  1
[<module>:77] 
[<module>:29]    37: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=e7d6, opcode=0 (QUERY), rcode=3 (NXDOMAIN)
[<module>:46]        Query list (1 items)
[<module>:48]           winterpark-info.com.multi.uribl.com.	  1
[<module>:53]        Response list empty
[<module>:64]        Authority list (1 items)
[<module>:67]           multi.uribl.com.	300	SOA	uribl.com. dnsadmin.uribl.com. 1206986781 900 450 604800 300
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    38: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=aea2, opcode=0 (QUERY), rcode=3 (NXDOMAIN)
[<module>:46]        Query list (1 items)
[<module>:48]           100.110.225.207.sa-other.bondedsender.org.	 16
[<module>:53]        Response list empty
[<module>:62]        Authority list empty
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    39: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=6363, opcode=0 (QUERY), rcode=3 (NXDOMAIN)
[<module>:46]        Query list (1 items)
[<module>:48]           cmail2.com.multi.uribl.com.	  1
[<module>:53]        Response list empty
[<module>:64]        Authority list (1 items)
[<module>:67]           multi.uribl.com.	300	SOA	uribl.com. dnsadmin.uribl.com. 1206986781 900 450 604800 300
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    40: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=506d, opcode=0 (QUERY), rcode=3 (NXDOMAIN)
[<module>:46]        Query list (1 items)
[<module>:48]           100.110.225.207.bl.spamcop.net.	 16
[<module>:53]        Response list empty
[<module>:64]        Authority list (1 items)
[<module>:67]           bl.spamcop.net.	  0	SOA	bl.spamcop.net. hostmaster.admin.spamcop.net. 1206986451 3600 1800 3600 0
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    41: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=bb3d, opcode=0 (QUERY), rcode=3 (NXDOMAIN)
[<module>:46]        Query list (1 items)
[<module>:48]           signature-ad.com.multi.uribl.com.	  1
[<module>:53]        Response list empty
[<module>:64]        Authority list (1 items)
[<module>:67]           multi.uribl.com.	300	SOA	uribl.com. dnsadmin.uribl.com. 1206986781 900 450 604800 300
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    42: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=2ae8, opcode=0 (QUERY), rcode=3 (NXDOMAIN)
[<module>:46]        Query list (1 items)
[<module>:48]           64.222.15.72.bl.spamcop.net.	 16
[<module>:53]        Response list empty
[<module>:64]        Authority list (1 items)
[<module>:67]           bl.spamcop.net.	  0	SOA	bl.spamcop.net. hostmaster.admin.spamcop.net. 1206986451 3600 1800 3600 0
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    43: 130.216.207.2 -> 193.226.99.18
[<module>:40]        query, ident=357a, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           193.50.136.89.in-addr.arpa.	 12
[<module>:77] 
[<module>:29]    44: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=d9e5, opcode=0 (QUERY), rcode=3 (NXDOMAIN)
[<module>:46]        Query list (1 items)
[<module>:48]           kremmlingchamber.com.multi.uribl.com.	  1
[<module>:53]        Response list empty
[<module>:64]        Authority list (1 items)
[<module>:67]           multi.uribl.com.	300	SOA	uribl.com. dnsadmin.uribl.com. 1206986781 900 450 604800 300
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    45: 195.149.158.2 -> 130.216.207.1
[<module>:40]        response, ident=1359, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           ad1.emediate.dk.	  1
[<module>:55]        Response list (1 items)
[<module>:58]           ad1.emediate.dk.	600	A	195.149.158.4
[<module>:64]        Authority list (2 items)
[<module>:67]           emediate.dk.	600	NS	ns1.emediate.dk.
[<module>:67]           emediate.dk.	600	NS	ns2.emediate.dk.
[<module>:73]        Additional list (2 items)
[<module>:76]           ns1.emediate.dk.	600	A	195.149.158.2
[<module>:76]           ns2.emediate.dk.	600	A	194.17.24.131
[<module>:77] 
[<module>:29]    46: 130.216.190.242 -> 130.216.1.1
[<module>:40]        query, ident=1d8f, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           ARTSMAIL1.ARTSNET.AUCKLAND.AC.NZ.	 15
[<module>:77] 
[<module>:29]    47: 130.216.1.1 -> 130.216.190.242
[<module>:40]        response, ident=1d8f, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           ARTSMAIL1.ARTSNET.AUCKLAND.AC.NZ.	 15
[<module>:53]        Response list empty
[<module>:64]        Authority list (1 items)
[<module>:67]           ARTSNET.AUCKLAND.AC.NZ.	1800	SOA	dns3.AUCKLAND.AC.NZ. soa.AUCKLAND.AC.NZ. 2004077433 10800 3600 2419200 1800
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    48: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=7703, opcode=0 (QUERY), rcode=3 (NXDOMAIN)
[<module>:46]        Query list (1 items)
[<module>:48]           64.222.15.72.sa-trusted.bondedsender.org.	 16
[<module>:53]        Response list empty
[<module>:62]        Authority list empty
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    49: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=7556, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           173.109.156.213.in-addr.arpa.	 12
[<module>:55]        Response list (1 items)
[<module>:58]           173.109.156.213.in-addr.arpa.	3600	PTR	109-173.echostar.pl.
[<module>:64]        Authority list (2 items)
[<module>:67]           109.156.213.in-addr.arpa.	3600	NS	red.echostar.pl.
[<module>:67]           109.156.213.in-addr.arpa.	3600	NS	green.echostar.pl.
[<module>:73]        Additional list (2 items)
[<module>:76]           red.echostar.pl.	64230	A	213.156.98.133
[<module>:76]           green.echostar.pl.	64230	A	213.156.98.141
[<module>:77] 
[<module>:29]    50: 203.27.227.124 -> 130.216.207.2
[<module>:40]        response, ident=3e46, opcode=0 (QUERY), rcode=5 (REFUSED)
[<module>:46]        Query list (1 items)
[<module>:48]           www.ewb.co.nz.	  1
[<module>:53]        Response list empty
[<module>:62]        Authority list empty
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    51: 130.216.207.2 -> 203.27.227.123
[<module>:40]        query, ident=58d9, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           www.ewb.co.nz.	  1
[<module>:77] 
[<module>:29]    52: 216.64.43.122 -> 130.216.197.6
[<module>:40]        query, ident=fb44, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           ec.auckland.ac.nz.	 16
[<module>:77] 
[<module>:29]    53: 130.216.197.6 -> 216.64.43.122
[<module>:40]        response, ident=fb44, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           ec.auckland.ac.nz.	 16
[<module>:53]        Response list empty
[<module>:64]        Authority list (1 items)
[<module>:67]           ec.auckland.ac.nz.	10800	SOA	kronos0.cs.auckland.ac.nz. bindadm.cs.auckland.ac.nz. 2008033100 3600 900 3600000 86400
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    54: 130.216.1.1 -> 130.216.191.251
[<module>:40]        response, ident=b506, opcode=0 (QUERY), rcode=3 (NXDOMAIN)
[<module>:46]        Query list (1 items)
[<module>:48]           80.12.190.137.bl.spamcop.net.	 16
[<module>:53]        Response list empty
[<module>:64]        Authority list (1 items)
[<module>:67]           bl.spamcop.net.	  0	SOA	bl.spamcop.net. hostmaster.admin.spamcop.net. 1206985551 3600 1800 3600 0
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    55: 130.216.1.1 -> 130.216.191.251
[<module>:40]        response, ident=3eee, opcode=0 (QUERY), rcode=3 (NXDOMAIN)
[<module>:46]        Query list (1 items)
[<module>:48]           3.63.237.62.bl.spamcop.net.	 16
[<module>:53]        Response list empty
[<module>:64]        Authority list (1 items)
[<module>:67]           bl.spamcop.net.	  0	SOA	bl.spamcop.net. hostmaster.admin.spamcop.net. 1206985551 3600 1800 3600 0
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    56: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=1800, opcode=0 (QUERY), rcode=2 (SERVFAIL)
[<module>:46]        Query list (1 items)
[<module>:48]           www.montevista.com.	  1
[<module>:53]        Response list empty
[<module>:62]        Authority list empty
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    57: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=27ed, opcode=0 (QUERY), rcode=2 (SERVFAIL)
[<module>:46]        Query list (1 items)
[<module>:48]           www.montevista.com.	  1
[<module>:53]        Response list empty
[<module>:62]        Authority list empty
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    58: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=1ff6, opcode=0 (QUERY), rcode=2 (SERVFAIL)
[<module>:46]        Query list (1 items)
[<module>:48]           www.montevista.com.	  1
[<module>:53]        Response list empty
[<module>:62]        Authority list empty
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    59: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=2049, opcode=0 (QUERY), rcode=2 (SERVFAIL)
[<module>:46]        Query list (1 items)
[<module>:48]           www.montevista.com.	  1
[<module>:53]        Response list empty
[<module>:62]        Authority list empty
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    60: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=37e4, opcode=0 (QUERY), rcode=2 (SERVFAIL)
[<module>:46]        Query list (1 items)
[<module>:48]           www.montevista.com.	  1
[<module>:53]        Response list empty
[<module>:62]        Authority list empty
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    61: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=0060, opcode=0 (QUERY), rcode=2 (SERVFAIL)
[<module>:46]        Query list (1 items)
[<module>:48]           www.montevista.com.	  1
[<module>:53]        Response list empty
[<module>:62]        Authority list empty
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    62: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=286d, opcode=0 (QUERY), rcode=2 (SERVFAIL)
[<module>:46]        Query list (1 items)
[<module>:48]           www.montevista.com.	  1
[<module>:53]        Response list empty
[<module>:62]        Authority list empty
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    63: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=0892, opcode=0 (QUERY), rcode=2 (SERVFAIL)
[<module>:46]        Query list (1 items)
[<module>:48]           www.montevista.com.	  1
[<module>:53]        Response list empty
[<module>:62]        Authority list empty
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    64: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=309d, opcode=0 (QUERY), rcode=2 (SERVFAIL)
[<module>:46]        Query list (1 items)
[<module>:48]           www.montevista.com.	  1
[<module>:53]        Response list empty
[<module>:62]        Authority list empty
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    65: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=08ae, opcode=0 (QUERY), rcode=2 (SERVFAIL)
[<module>:46]        Query list (1 items)
[<module>:48]           www.montevista.com.	  1
[<module>:53]        Response list empty
[<module>:62]        Authority list empty
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    66: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=10d2, opcode=0 (QUERY), rcode=2 (SERVFAIL)
[<module>:46]        Query list (1 items)
[<module>:48]           www.montevista.com.	  1
[<module>:53]        Response list empty
[<module>:62]        Authority list empty
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    67: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=38c9, opcode=0 (QUERY), rcode=2 (SERVFAIL)
[<module>:46]        Query list (1 items)
[<module>:48]           www.montevista.com.	  1
[<module>:53]        Response list empty
[<module>:62]        Authority list empty
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    68: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=30ef, opcode=0 (QUERY), rcode=2 (SERVFAIL)
[<module>:46]        Query list (1 items)
[<module>:48]           www.montevista.com.	  1
[<module>:53]        Response list empty
[<module>:62]        Authority list empty
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    69: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=00f4, opcode=0 (QUERY), rcode=2 (SERVFAIL)
[<module>:46]        Query list (1 items)
[<module>:48]           www.montevista.com.	  1
[<module>:53]        Response list empty
[<module>:62]        Authority list empty
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    70: 130.216.1.2 -> 130.216.190.242
[<module>:40]        response, ident=f41c, opcode=0 (QUERY), rcode=2 (SERVFAIL)
[<module>:46]        Query list (1 items)
[<module>:48]           www.montevista.com.	  1
[<module>:53]        Response list empty
[<module>:62]        Authority list empty
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    71: 130.216.1.1 -> 130.216.191.251
[<module>:40]        response, ident=3240, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           119.242.104.85.in-addr.arpa.	 12
[<module>:55]        Response list (1 items)
[<module>:58]           119.242.104.85.in-addr.arpa.	86400	PTR	dsl85-104-62071.ttnet.net.tr.
[<module>:64]        Authority list (3 items)
[<module>:67]           104.85.in-addr.arpa.	55751	NS	ns.ripe.net.
[<module>:67]           104.85.in-addr.arpa.	55751	NS	ns1.ttnet.net.tr.
[<module>:67]           104.85.in-addr.arpa.	55751	NS	ns2.ttnet.net.tr.
[<module>:73]        Additional list (2 items)
[<module>:76]           ns.ripe.net.	9401	A	193.0.0.193
[<module>:76]           ns.ripe.net.	107699	AAAA	2001:610:240:0:53::193
[<module>:77] 
[<module>:29]    72: 130.216.190.242 -> 130.216.1.1
[<module>:40]        query, ident=bb93, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           gate.student.auckland.ac.nz.	  1
[<module>:77] 
[<module>:29]    73: 130.216.1.1 -> 130.216.190.242
[<module>:40]        response, ident=bb93, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           gate.student.auckland.ac.nz.	  1
[<module>:55]        Response list (1 items)
[<module>:58]           gate.student.auckland.ac.nz.	10800	A	130.216.191.182
[<module>:64]        Authority list (6 items)
[<module>:67]           student.auckland.ac.nz.	10800	NS	kronos1.cs.auckland.ac.nz.
[<module>:67]           student.auckland.ac.nz.	10800	NS	kronos2.cs.auckland.ac.nz.
[<module>:67]           student.auckland.ac.nz.	10800	NS	kronos3.tcs.auckland.ac.nz.
[<module>:67]           student.auckland.ac.nz.	10800	NS	kronos4.tcs.auckland.ac.nz.
[<module>:67]           student.auckland.ac.nz.	10800	NS	dns1.auckland.ac.nz.
[<module>:67]           student.auckland.ac.nz.	10800	NS	dns2.auckland.ac.nz.
[<module>:73]        Additional list (6 items)
[<module>:76]           dns1.auckland.ac.nz.	1800	A	130.216.1.2
[<module>:76]           dns2.auckland.ac.nz.	1800	A	130.216.1.1
[<module>:76]           kronos1.cs.auckland.ac.nz.	10800	A	130.216.35.35
[<module>:76]           kronos2.cs.auckland.ac.nz.	10800	A	130.216.35.135
[<module>:76]           kronos3.tcs.auckland.ac.nz.	1800	A	130.216.207.52
[<module>:76]           kronos4.tcs.auckland.ac.nz.	1800	A	130.216.197.6
[<module>:77] 
[<module>:29]    74: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=0fa7, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           cmail2.com.	 15
[<module>:55]        Response list (1 items)
[<module>:58]           cmail2.com.	1800	MX	10 mx1.cmail2.com.
[<module>:64]        Authority list (5 items)
[<module>:67]           cmail2.com.	7033	NS	ns2.dnsmadeeasy.com.
[<module>:67]           cmail2.com.	7033	NS	ns3.dnsmadeeasy.com.
[<module>:67]           cmail2.com.	7033	NS	ns4.dnsmadeeasy.com.
[<module>:67]           cmail2.com.	7033	NS	ns0.dnsmadeeasy.com.
[<module>:67]           cmail2.com.	7033	NS	ns1.dnsmadeeasy.com.
[<module>:73]        Additional list (6 items)
[<module>:76]           mx1.cmail2.com.	1800	A	72.15.222.72
[<module>:76]           ns0.dnsmadeeasy.com.	26053	A	63.219.151.3
[<module>:76]           ns1.dnsmadeeasy.com.	85900	A	205.234.154.1
[<module>:76]           ns2.dnsmadeeasy.com.	36863	A	66.117.40.198
[<module>:76]           ns3.dnsmadeeasy.com.	32655	A	216.129.109.1
[<module>:76]           ns4.dnsmadeeasy.com.	28293	A	205.234.170.165
[<module>:77] 
[<module>:29]    75: 130.216.1.1 -> 130.216.190.242
[<module>:40]        response, ident=e2fd, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           bcn.gob.ni.	 28
[<module>:53]        Response list empty
[<module>:64]        Authority list (1 items)
[<module>:67]           bcn.gob.ni.	10800	SOA	sweb2.bcn.gob.ni. root.sweb2.bcn.gob.ni. 2008022303 10800 3600 604800 86400
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    76: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=2ffa, opcode=0 (QUERY), rcode=2 (SERVFAIL)
[<module>:46]        Query list (1 items)
[<module>:48]           www.ewb.co.nz.	  1
[<module>:53]        Response list empty
[<module>:62]        Authority list empty
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    77: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=32e9, opcode=0 (QUERY), rcode=2 (SERVFAIL)
[<module>:46]        Query list (1 items)
[<module>:48]           www.ewb.co.nz.	  1
[<module>:53]        Response list empty
[<module>:62]        Authority list empty
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    78: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=2196, opcode=0 (QUERY), rcode=2 (SERVFAIL)
[<module>:46]        Query list (1 items)
[<module>:48]           www.ewb.co.nz.	  1
[<module>:53]        Response list empty
[<module>:62]        Authority list empty
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    79: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=1fc0, opcode=0 (QUERY), rcode=2 (SERVFAIL)
[<module>:46]        Query list (1 items)
[<module>:48]           www.ewb.co.nz.	  1
[<module>:53]        Response list empty
[<module>:62]        Authority list empty
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    80: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=1af2, opcode=0 (QUERY), rcode=2 (SERVFAIL)
[<module>:46]        Query list (1 items)
[<module>:48]           www.ewb.co.nz.	  1
[<module>:53]        Response list empty
[<module>:62]        Authority list empty
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    81: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=12ff, opcode=0 (QUERY), rcode=2 (SERVFAIL)
[<module>:46]        Query list (1 items)
[<module>:48]           www.ewb.co.nz.	  1
[<module>:53]        Response list empty
[<module>:62]        Authority list empty
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    82: 130.216.190.242 -> 130.216.1.1
[<module>:40]        query, ident=5030, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           69inch.com.	  1
[<module>:77] 
[<module>:29]    83: 130.216.1.1 -> 130.216.190.242
[<module>:40]        response, ident=5030, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           69inch.com.	  1
[<module>:55]        Response list (1 items)
[<module>:58]           69inch.com.	579	A	82.98.86.170
[<module>:64]        Authority list (2 items)
[<module>:67]           69inch.com.	6645	NS	ns1.sedoparking.com.
[<module>:67]           69inch.com.	6645	NS	ns2.sedoparking.com.
[<module>:73]        Additional list (8 items)
[<module>:76]           ns1.sedoparking.com.	31451	A	217.160.186.74
[<module>:76]           ns1.sedoparking.com.	31451	A	74.208.13.27
[<module>:76]           ns1.sedoparking.com.	31451	A	91.195.240.162
[<module>:76]           ns1.sedoparking.com.	31451	A	212.227.86.6
[<module>:76]           ns2.sedoparking.com.	31451	A	74.208.8.95
[<module>:76]           ns2.sedoparking.com.	31451	A	87.106.54.143
[<module>:76]           ns2.sedoparking.com.	31451	A	91.195.241.162
[<module>:76]           ns2.sedoparking.com.	31451	A	217.160.208.235
[<module>:77] 
[<module>:29]    84: 130.216.191.251 -> 130.216.1.1
[<module>:40]        query, ident=22ab, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           50.130.78.202.bl.spamcop.net.	 16
[<module>:77] 
[<module>:29]    85: 130.216.207.1 -> 67.134.221.6
[<module>:40]        query, ident=c825, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           booneoms.com.	 15
[<module>:77] 
[<module>:29]    86: 130.216.207.1 -> 208.184.22.154
[<module>:40]        query, ident=f2cd, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           imagevenue.com.multi.uribl.com.	  1
[<module>:77] 
[<module>:29]    87: 130.216.1.1 -> 130.216.190.242
[<module>:40]        response, ident=c1df, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           cpc3-oldh3-0-0-cust576.manc.cable.ntl.com.	  1
[<module>:55]        Response list (1 items)
[<module>:58]           cpc3-oldh3-0-0-cust576.manc.cable.ntl.com.	604800	A	86.1.242.65
[<module>:64]        Authority list (4 items)
[<module>:67]           manc.cable.ntl.com.	348375	NS	ns4.virginmedia.net.
[<module>:67]           manc.cable.ntl.com.	348375	NS	ns1.virginmedia.net.
[<module>:67]           manc.cable.ntl.com.	348375	NS	ns2.virginmedia.net.
[<module>:67]           manc.cable.ntl.com.	348375	NS	ns3.virginmedia.net.
[<module>:73]        Additional list (4 items)
[<module>:76]           ns1.virginmedia.net.	99714	A	62.253.162.237
[<module>:76]           ns2.virginmedia.net.	99714	A	194.168.4.237
[<module>:76]           ns3.virginmedia.net.	99714	A	62.253.162.37
[<module>:76]           ns4.virginmedia.net.	99714	A	194.168.4.33
[<module>:77] 
[<module>:29]    88: 77.221.130.250 -> 130.216.207.2
[<module>:40]        response, ident=e6a3, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           mail.tkhost.ru.	  1
[<module>:55]        Response list (1 items)
[<module>:58]           mail.tkhost.ru.	600	A	77.221.135.97
[<module>:64]        Authority list (2 items)
[<module>:67]           tkhost.ru.	600	NS	ns1.infobox.org.
[<module>:67]           tkhost.ru.	600	NS	ns2.infobox.org.
[<module>:73]        Additional list (1 items)
[<module>:76]           ns2.infobox.org.	634	A	77.221.128.22
[<module>:77] 
[<module>:29]    89: 213.133.103.28 -> 130.216.207.2
[<module>:40]        query, ident=9ef4, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           chico.itss.auckland.ac.nz.	 28
[<module>:77] 
[<module>:29]    90: 203.27.227.123 -> 130.216.207.1
[<module>:40]        response, ident=9ef0, opcode=0 (QUERY), rcode=5 (REFUSED)
[<module>:46]        Query list (1 items)
[<module>:48]           www.ewb.co.nz.	  1
[<module>:53]        Response list empty
[<module>:62]        Authority list empty
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    91: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=6163, opcode=0 (QUERY), rcode=3 (NXDOMAIN)
[<module>:46]        Query list (1 items)
[<module>:48]           64.222.15.72.zen.spamhaus.org.	  1
[<module>:53]        Response list empty
[<module>:64]        Authority list (1 items)
[<module>:67]           zen.spamhaus.org.	900	SOA	need.to.know.only. hostmaster.spamhaus.org. 2008033172 3600 600 432000 900
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    92: 130.216.207.1 -> 203.27.227.124
[<module>:40]        query, ident=0f63, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           www.ewb.co.nz.	  1
[<module>:77] 
[<module>:29]    93: 130.216.1.1 -> 130.216.191.251
[<module>:40]        response, ident=c050, opcode=0 (QUERY), rcode=3 (NXDOMAIN)
[<module>:46]        Query list (1 items)
[<module>:48]           80.12.190.137.sa-other.bondedsender.org.	 16
[<module>:53]        Response list empty
[<module>:62]        Authority list empty
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    94: 130.216.1.1 -> 130.216.191.251
[<module>:40]        response, ident=aca6, opcode=0 (QUERY), rcode=3 (NXDOMAIN)
[<module>:46]        Query list (1 items)
[<module>:48]           3.63.237.62.sa-trusted.bondedsender.org.	 16
[<module>:53]        Response list empty
[<module>:62]        Authority list empty
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    95: 130.216.1.2 -> 130.216.191.251
[<module>:40]        response, ident=6e4d, opcode=0 (QUERY), rcode=3 (NXDOMAIN)
[<module>:46]        Query list (1 items)
[<module>:48]           100.110.225.207.zen.spamhaus.org.	  1
[<module>:53]        Response list empty
[<module>:64]        Authority list (1 items)
[<module>:67]           zen.spamhaus.org.	900	SOA	need.to.know.only. hostmaster.spamhaus.org. 2008033172 3600 600 432000 900
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:29]    96: 209.160.34.46 -> 130.216.207.1
[<module>:40]        response, ident=1cb1, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           www.indiantelephones.com.	  1
[<module>:53]        Response list empty
[<module>:64]        Authority list (2 items)
[<module>:67]           indiantelephones.com.	11217	NS	dns2.s2lservers.com.
[<module>:67]           indiantelephones.com.	11217	NS	dns1.s2lservers.com.
[<module>:73]        Additional list (2 items)
[<module>:76]           dns1.s2lservers.com.	14095	A	209.160.32.39
[<module>:76]           dns2.s2lservers.com.	14095	A	209.160.34.46
[<module>:77] 
[<module>:29]    97: 130.216.207.1 -> 209.160.32.39
[<module>:40]        query, ident=c7c8, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           www.indiantelephones.com.	  1
[<module>:77] 
[<module>:29]    98: 130.216.191.251 -> 130.216.1.1
[<module>:40]        query, ident=613e, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           82-46-143-39.cable.ubr02.harb.blueyonder.co.uk.	  1
[<module>:77] 
[<module>:29]    99: 130.216.207.1 -> 69.28.95.26
[<module>:40]        query, ident=c77c, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           214.10.209.60.combined.njabl.org.	  1
[<module>:77] 
[<module>:29]   100: 211.24.154.146 -> 130.216.207.2
[<module>:40]        response, ident=00df, opcode=0 (QUERY), rcode=0 (NOERROR)
[<module>:46]        Query list (1 items)
[<module>:48]           www.osram.com.	  1
[<module>:55]        Response list (1 items)
[<module>:58]           www.osram.com.	 60	A	194.138.18.111
[<module>:62]        Authority list empty
[<module>:71]        Additional list empty
[<module>:77] 
[<module>:84] 100 packets read
