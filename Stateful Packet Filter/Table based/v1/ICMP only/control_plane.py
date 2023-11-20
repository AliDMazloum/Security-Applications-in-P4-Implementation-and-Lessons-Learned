import json
import time
from datetime import datetime,timezone
import threading
import socket
import atexit


p4 = bfrt.Lessons_learned_firewall.pipe

p4_c2s = p4.Ingress.c2s_filter
p4_s2c = p4.Ingress.s2c_filter

p4_c2s.add_with_notify_control_plane_c2s(src_addr="50.0.0.0", src_addr_p_length = 24)

def add_s2c_rule(dev_id, pipe_id, direction, parser_id, session, msg):
    global p4_s2c
    import ipaddress
    for digest in msg:
        src_addr = ipaddress.ip_address(digest['src_addr'])
        dst_addr = ipaddress.ip_address(digest['dst_addr'])
        icmp_id = digest['icmp_id']
        print("Adding: ",src_addr,dst_addr,icmp_id)
        p4_s2c.add_with_notify_control_plane_s2c(src_addr=dst_addr, dst_addr = src_addr,identifier=icmp_id)
    return 0
        
def remove_s2c_rule(dev_id, pipe_id, direction, parser_id, session, msg):
    import ipaddress
    for digest in msg:
        src_addr = ipaddress.ip_address(digest['src_addr'])
        dst_addr = ipaddress.ip_address(digest['dst_addr'])
        icmp_id = digest['icmp_id']
        print("Deleting: ",src_addr,dst_addr,icmp_id)
        p4_s2c.delete(src_addr=src_addr, dst_addr = dst_addr,identifier=icmp_id)
    return 0
        


try:
    p4.IngressDeparser.add_sc2_rule.callback_register(add_s2c_rule)
    p4.IngressDeparser.remove_sc2_rule.callback_register(remove_s2c_rule)
except:
    print('Error registering callback')
    
print("Ali")