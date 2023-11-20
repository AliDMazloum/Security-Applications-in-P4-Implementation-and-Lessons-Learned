import json
import time
from datetime import datetime,timezone
import threading
import socket
import atexit


p4 = bfrt.Registers_firewall.pipe

p4_icmp_c2s = p4.Ingress.c2s_icmp_filter

p4_tcp_c2s = p4.Ingress.c2s_tcp_filter

p4_icmp_c2s.add_with_NoAction(src_addr="50.0.0.0", src_addr_p_length = 24,dst_addr="80.0.0.0",dst_addr_mask="0.0.0.0",MATCH_PRIORITY=0)
p4_tcp_c2s.add_with_NoAction(src_addr="50.0.0.0", src_addr_p_length = 24,dst_addr="80.0.0.0",dst_addr_mask="0.0.0.0",MATCH_PRIORITY=0)

def icmp_accepted(dev_id, pipe_id, direction, parser_id, session, msg):
    import ipaddress
    for digest in msg:
        src_addr = ipaddress.ip_address(digest['src_addr'])
        dst_addr = ipaddress.ip_address(digest['dst_addr'])
        icmp_id = digest['icmp_id']
        print("Adding: ",src_addr,dst_addr,icmp_id)
    return 0

def tcp_accepted(dev_id, pipe_id, direction, parser_id, session, msg):
    import ipaddress
    for digest in msg:
        src_addr = ipaddress.ip_address(digest['src_addr'])
        dst_addr = ipaddress.ip_address(digest['dst_addr'])
        src_port = digest['src_port']
        dst_port = digest['dst_port']
        print("Adding: ",src_addr, dst_addr, src_port, dst_port)
    return 0

try:
    p4.IngressDeparser.icmp_accepted.callback_register(icmp_accepted)
    p4.IngressDeparser.tcp_accepted.callback_register(tcp_accepted)
except:
    print('Error registering callback')