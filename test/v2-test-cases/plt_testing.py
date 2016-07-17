# Thu, 13 Mar 14 (PDT)
# plt-testing.py:  Support routines for testing python-libtrace
# Copyright (C) 2015, Nevil Brownlee, U Auckland | WAND

import plt  # Also imports ipp and datetime

import os      # Contains getcwd
import sys     #   exit and stdout
import re      #   regular expressions
# import socket  #   gethostname
import inspect

def get_example_trace(fn, show_full_fn=False):
    cwd = os.getcwd()
    basename = os.path.basename(cwd)
    if re.match(r'python-libtrace', basename):
        full_fn = 'pcapfile:' + cwd + '/doc/examples/' + fn
    else:
        full_fn = 'pcapfile:' + cwd + '/' + fn
    if show_full_fn:
        print get_tag()+"fullfn = {0}\n" . format(full_fn)
    else:
        print get_tag()+"fn = {0}\n" . format(fn)

    t = plt.trace(full_fn)
    t.start()
    return t

def print_data(msg, offset, data, mxlen, tag=''):
    blanks = ' ' * (offset-1)   # print outputs an extra blank
    pad = ' ' * (offset - len(msg) + 1)  # Don't change (caller's) msg!
    print tag+get_tag(), " %s%s" % (msg, pad),  # Trailing comma suppresses the linefeed
    for j in range(len(data)):
        if j == mxlen:
            break
        if j % 32 == 0 and j != 0:
            print "\n%s%s" % (tag+get_tag(),blanks),
        if j % 8 == 0 and j != 0:
            print ' ',
        print "%02x" % (data[j]),
    print

def print_ip(ip, offset, tag=''):
    margin = ' ' * offset
    print tag+get_tag()+" %s -> %s, proto=%d, tclass=%x," % (
        ip.src_prefix, ip.dst_prefix, ip.proto, ip.traffic_class)
    print tag+get_tag()+" %sttl=%d, hlen=%d, plen=%d, " % (
        margin, ip.ttl, ip.hdr_len, ip.pkt_len),
    print "mf=%s, frag_offset=%d, ident=%04x" % (
        ip.has_mf, ip.frag_offset, ip.ident)
    
def print_ip6(ip6, offset, tag=''):
    margin = ' ' * offset
    print tag+get_tag()+" %s -> %s, proto=%d, tclass=%x," % (
        ip6.src_prefix, ip6.dst_prefix, ip6.proto, ip6.traffic_class)
    print tag+get_tag()+" %sttl=%d, hlen=%s, plen=%s" % (
        margin, ip6.hop_limit, ip6.hdr_len, ip6.pkt_len),
    print "flow_label=%x, payload_len=%d, next_hdr=%d" % (
        ip6.flow_label, ip6.payload_len, ip6.next_hdr)
    
def print_tcp(tcp, margin, tag=''):
    fl = ''
    if tcp.urg_flag:
        fl += 'U'
    if tcp.psh_flag:
        fl += 'P'
    if tcp.rst_flag:
        fl += 'R'
    if tcp.fin_flag:
        fl += 'F'
    if tcp.syn_flag:
        fl += 'S'
    if tcp.ack_flag:
        fl += 'A'
    print tag+get_tag()+" TCP, %s -> %s, %d -> %d, seq=%u, ack=%u" % (
        tcp.src_prefix, tcp.dst_prefix, tcp.src_port, tcp.dst_port,
        tcp.seq_nbr, tcp.ack_nbr)
    print tag+get_tag()+"          flags=%02x (%s), window=%u, checksum=%x, urg_ptr=%u" % (
        tcp.flags, fl, tcp.window, tcp.checksum, tcp.urg_ptr)
    payload = tcp.payload
    if not payload:
        print tag+get_tag()+"          "+"no payload"
    else:
        pd = payload.data
        print_data("\n"+tag+get_tag()+"          payload:", margin, pd, 64, tag+get_tag())

def print_udp(udp, margin, tag=''):
    print tag+get_tag()+" UDP, src_port=%u, dest_port=%u, len=%u, checksum=%04x" % (
        udp.src_port, udp.dst_port, udp.len, udp.checksum)
    t = (' ' * 8) + 'UDP'
#    print_data(t, margin, udp.data, 64)

def print_icmp_ip(p, margin, tag=''):
    print tag+get_tag()+" proto=%d, TTL=%d, pkt_len=%d" % (
       p.proto, p.ttl, p.pkt_len)

def print_icmp(icmp, offset, tag=''):  # IPv4 only  (IPv6 uses ICMP6 protocol)
    margin = ' ' * offset
    print tag+get_tag()+"%sICMP, type=%u, code=%u, checksum=%04x,  wlen=%d, clen=%d, %s" % (
        margin, icmp.type, icmp.code, icmp.checksum,
        icmp.wire_len, icmp.capture_len, icmp.time)
    type = icmp.type;  p = icmp.payload;  pt = 'IP  '
    if type == 0 or type == 8:  # Echo Reply, Echo Request
        if type == 8:
            which = 'request,'
        else:
            which = 'reply,  '
        echo = icmp.echo
        print tag+get_tag()+"%sEcho %s ident=%04x, sequence=%d" % (
            margin, which, echo.ident, echo.sequence)
        pt = 'Echo'
    elif type == 3:  # Destination Unreachable
        print tag+get_tag()+"%sDestination unreachable," % (margin),
        print_icmp_ip(p, margin)
    elif type == 4:  # Source Quench
        print tag+"%sSource quench," % (margin),
        print_icmp_ip(p, margin)
    elif type == 5:  # Redirect
        redirect = icmp.redirect;
        print tag+"%sRedirect, gateway=%s," % (margin, redirect.gateway),
        print_icmp_ip(p, margin)
    elif type == 11:  # Time Exceeded
        print tag+"%sTime exceeded," % (margin),
        print_icmp_ip(p, margin)
    else:
        print tag+get_tag()+" %sOther,",
        pt = 'Data:'
        print_icmp_ip(p,margin)
    t = margin + pt
    print_data(t, offset+len(pt), p.data, 64, tag+get_tag())

def print_ip6_info(ip6, tag=''):
    print tag+get_tag()+" %s -> %s, TTL=%d" % (
            ip6.src_prefix, ip6.dst_prefix, ip6.ttl)


def print_icmp6(icmp6, offset, tag=''):  # IPv6 only
    margin = ' ' * (offset-3)
    print tag+get_tag()+"%sICMP6: stype=%u, code=%u, checksum=%04x, wlen=%d, clen=%d, %s" % (
        margin, icmp6.type, icmp6.code, icmp6.checksum,
        icmp6.wire_len, icmp6.capture_len, icmp6.time)
    margin = ' ' * offset
    type = icmp6.type;  p = icmp6.payload;  pt = 'Echo'
    if type == 1:  # Destination Unreachable
        print tag+get_tag()+"%sDestination unreachable:" % (margin),
        pt = 'IP6 '
        print_ip6_info(p)
    elif type == 128 or type == 129:  # Echo Request, Echo Reply
        if type == 128:
            which = 'request:'
        else:
            which = 'reply:  '
        echo = icmp6.echo
        print tag+"%sEcho %s ident=%04x, sequence=%d" % (
            margin, which, echo.ident, echo.sequence)
        pt = 'Data'
    elif type == 2:  # Packet Too Big
        print tag+get_tag()+"%sPacket Too Big; MTU=%d:" % (margin, icmp6.toobig.mtu),
        pt = 'IP  '
        print_ip6_info(p)
    elif type == 3:  # Time Exceeded
        print tag+get_tag()+"%sTime Exceeded:" % (margin),
        pt = 'IP6 '
        print_ip6_info(p)
    elif type == 4:  # Parameter Problem
        print tag+get_tag()+"%sParameter Problem; pointer=%d," % (margin, icmp6.param.pointer),
        pt = 'IP6 '
        print_ip6_info(p)
    else:
        if type == 133:
            s = "Router Solicitation"
        elif type == 134:
            s = "Router Advertisment"
        elif type == 135:
            s = "Neighbour Solicitation"
        elif type == 136:
            s = "Neighbour Advertisment"
        elif type == 137:
            s = "Redirect"
        elif type ==138:
            s = "Router Renumbering"
        else:
            s = "Other"
        if type == 135 or type == 136:
            print tag+get_tag()+"%s%s: target_prefix=%s, src_prefix=%s" % (
                margin, s, icmp6.neighbour.target_prefix, icmp6.src_prefix)
        else:
            print tag+get_tag()+"%s%s: src_prefix=%s" % (margin, s, icmp6.src_prefix)
        pt = 'Data'
    t = margin + pt
    print_data(t, offset+3, p.data, 64, tag+get_tag())

def test_print(message, tag=''):
    if tag == '':
        print message,
    else:
        print tag+ ' '+message,


def test_println(message, tag=''):
    print tag+' '+message

def get_tag(message=None):
    (frame, filename, line_number,
     function_name, lines, index) = inspect.getouterframes(inspect.currentframe())[1]
    if message == None:
        return '['+function_name+':'+str(line_number)+']'
    else:
        return '['+function_name+':'+str(line_number)+':'+'{'+message+'}'+']'
