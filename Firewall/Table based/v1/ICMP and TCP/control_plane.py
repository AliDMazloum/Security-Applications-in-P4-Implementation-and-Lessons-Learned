import json
import time
from datetime import datetime,timezone
import threading
import socket
import atexit


p4 = bfrt.Lessons_learned_firewall.pipe

p4_icmp_c2s = p4.Ingress.c2s_icmp_filter
p4_icmp_s2c = p4.Ingress.s2c_icmp_filter

p4_tcp_c2s = p4.Ingress.c2s_tcp_filter
p4_tcp_s2c = p4.Ingress.s2c_tcp_filter

p4_icmp_c2s.add_with_notify_control_plane_icmp_c2s(src_addr="50.0.0.0", src_addr_p_length = 24,dst_addr="80.0.0.0",dst_addr_mask="0.0.0.0",MATCH_PRIORITY=0)
p4_tcp_c2s.add_with_notify_control_plane_tcp_c2s(src_addr="50.0.0.0", src_addr_p_length = 24,dst_addr="80.0.0.0",dst_addr_mask="0.0.0.0",MATCH_PRIORITY=0)


def add_icmp_s2c_rule(dev_id, pipe_id, direction, parser_id, session, msg):
    global p4_icmp_s2c
    import ipaddress
    for digest in msg:
        src_addr = ipaddress.ip_address(digest['src_addr'])
        dst_addr = ipaddress.ip_address(digest['dst_addr'])
        icmp_id = digest['icmp_id']
        print("Adding: ",src_addr,dst_addr,icmp_id)
        p4_icmp_s2c.add_with_notify_control_plane_icmp_s2c(src_addr=dst_addr, dst_addr = src_addr,identifier=icmp_id)
    return 0
        
def remove_icmp_s2c_rule(dev_id, pipe_id, direction, parser_id, session, msg):
    import ipaddress
    for digest in msg:
        src_addr = ipaddress.ip_address(digest['src_addr'])
        dst_addr = ipaddress.ip_address(digest['dst_addr'])
        icmp_id = digest['icmp_id']
        print("Deleting: ",src_addr,dst_addr,icmp_id)
        p4_icmp_s2c.delete(src_addr=src_addr, dst_addr = dst_addr,identifier=icmp_id)
    return 0

def add_tcp_s2c_rule(dev_id, pipe_id, direction, parser_id, session, msg):
    import ipaddress
    global p4_tcp_s2c
    for digest in msg:
        src_addr = ipaddress.ip_address(digest['src_addr'])
        dst_addr = ipaddress.ip_address(digest['dst_addr'])
        src_port = digest['src_port']
        dst_port = digest['dst_port']
        print("Adding: ",src_addr, dst_addr, src_port, dst_port)
        p4_tcp_s2c.add_with_tcp_s2c(src_addr=dst_addr, dst_addr = src_addr,src_port=dst_port, dst_port=src_port, ENTRY_TTL = 500)
        # p4_tcp_s2c.add_with_meter(src_addr=dst_addr, dst_addr = src_addr,src_port=dst_port, dst_port=src_port, ENTRY_TTL = 500)
    return 0

def remove_tcp_s2c_rule(dev_id, pipe_id, direction, parser_id, entry):
    import ipaddress
    try:
        # flow_id = entry.key[b'meta.flow_id']
        src_addr = ipaddress.ip_address(entry.key[b'hdr.ipv4.src_addr'])
        dst_addr = ipaddress.ip_address(entry.key[b'hdr.ipv4.dst_addr'])
        src_port = entry.key[b'hdr.tcp.src_port']
        dst_port = entry.key[b'hdr.tcp.dst_port']
        print("Deleting: ",src_addr, dst_addr, src_port, dst_port)
        p4_tcp_s2c.delete(src_addr=src_addr, dst_addr = dst_addr,src_port = src_port, dst_port = dst_port)
    except Exception as e:
        print("Error in remove_tcp_s2c_rule: ",e)
    

try:
    p4.IngressDeparser.add_icmp_sc2_rule.callback_register(add_icmp_s2c_rule)
    p4.IngressDeparser.remove_icmp_sc2_rule.callback_register(remove_icmp_s2c_rule)
    p4.IngressDeparser.add_tcp_sc2_rule.callback_register(add_tcp_s2c_rule)
    # p4.IngressDeparser.remove_tcp_sc2_rule.callback_register(remove_tcp_s2c_rule)
    p4.Ingress.s2c_tcp_filter.idle_table_set_notify(enable=True, callback=remove_tcp_s2c_rule, interval=200, min_ttl=0, max_ttl=0)

except:
    print('Error registering callback')
    
print("Ali")