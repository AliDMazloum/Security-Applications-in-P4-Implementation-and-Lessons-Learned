/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>
#include "Headers_and_Definitions.p4"



struct icmp_id_digest_t {
    bit<32> src_addr;
    bit<32> dst_addr; 
    bit<16> icmp_id;
}

struct tcp_digest_t {
    bit<32> src_addr;
    bit<32> dst_addr;
    bit<16> src_port;
    bit<16> dst_port; 
}

  

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/
    struct my_ingress_headers_t {
        ethernet_h   ethernet;
        ipv4_h       ipv4;
        tcp_h        tcp;
        udp_h        udp;
        icmp_t       icmp;
        rtp_h        rtp;


    }
    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/
    struct my_ingress_metadata_t {
		bit<9> in_port;
        bit<11> flow_id;
        bit<16> icmp_id;
    }
    /***********************  P A R S E R  **************************/
    parser IngressParser(packet_in        pkt,
        /* User */
        out my_ingress_headers_t          hdr,
        out my_ingress_metadata_t         meta,
        /* Intrinsic */
        out ingress_intrinsic_metadata_t  ig_intr_md)
        {
            /* This is a mandatory state, required by Tofino Architecture */
            state start {
                pkt.extract(ig_intr_md);
                pkt.advance(PORT_METADATA_SIZE);
                transition parse_ethernet;
            }

            state parse_ethernet {
                pkt.extract(hdr.ethernet);
                transition select(hdr.ethernet.ether_type) {
                    ETHERTYPE_IPV4:  parse_ipv4;
                    default: accept;
                }
            }

            state parse_ipv4 {
                pkt.extract(hdr.ipv4);
                transition select(hdr.ipv4.protocol) {
                    TYPE_TCP: parse_tcp;
                    TYPE_UDP: parse_udp;
                    TYPE_ICMP: parse_icmp;
                    default: accept;
                }
            }

            state parse_tcp {
                pkt.extract(hdr.tcp);
                transition accept;
            }

            state parse_udp {
                pkt.extract(hdr.udp);
                transition parse_rtp;
            }
            state parse_icmp {
                pkt.extract(hdr.icmp);
                transition parse_rtp;
            }
            
            state parse_rtp {
                pkt.extract(hdr.rtp);
                transition accept;
            }


        }


    /***************** M A T C H - A C T I O N  *********************/
    control Ingress(
        /* User */
        inout my_ingress_headers_t                       hdr,
        inout my_ingress_metadata_t                      meta,
        /* Intrinsic */
        in    ingress_intrinsic_metadata_t               ig_intr_md,
        in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
        {

            /*********************Hashing**************************/

                Hash<bit<11>>(HashAlgorithm_t.CRC16) hash;
                action apply_hash() {
                    meta.flow_id = hash.get({
                        hdr.ipv4.src_addr,
                        hdr.ipv4.dst_addr,
                        hdr.ipv4.protocol,
                        hdr.tcp.src_port,
                        hdr.tcp.dst_port
                                        });
                                    }

                table calc_flow_id {
                    actions = {
                        apply_hash;
                    }
                    const default_action = apply_hash();
                }
            /*********************End Hashing**********************/

            /***********************Actions************************/
                action drop() {
                    ig_dprsr_md.drop_ctl = 0x1; // Drop packet.
                } 
            
                action notify_control_plane_icmp_c2s() {
                    ig_dprsr_md.digest_type = 0;
                    //Specify the egress port for ECHO packets
                    ig_tm_md.ucast_egress_port = 1;
                }

                action notify_control_plane_icmp_s2c() {
                    ig_dprsr_md.digest_type = 1;
                    //Specify the egress port for REPLY packets
                    ig_tm_md.ucast_egress_port = 0;
                }

                action notify_control_plane_tcp_c2s() {
                    ig_dprsr_md.digest_type = 2;
                    //Specify the egress port for ECHO packets
                    ig_tm_md.ucast_egress_port = 1;
                }

                action tcp_s2c() {
                    // ig_dprsr_md.digest_type = 3;
                    //Specify the egress port for REPLY packets
                    ig_tm_md.ucast_egress_port = 0;
                }

                action meter(){
                }

            /*********************End Actions***********************/


            /************************ICMP**************************/
            table c2s_icmp_filter {
                key = {
                    hdr.ipv4.src_addr: lpm;
                    hdr.ipv4.dst_addr: ternary;
                }
                actions = {
                    notify_control_plane_icmp_c2s;
                    drop;
                }
                size = 1024;
            }

            table s2c_icmp_filter {
                key = {
                    hdr.ipv4.src_addr: exact;
                    hdr.ipv4.dst_addr: exact;
                    hdr.icmp.identifier:exact;
                    // hdr.ipv4.dstAddr: ternary;
                }
                actions = {
                    notify_control_plane_icmp_s2c;
                    drop;
                }
                size = 1024;
            }

            /***********************End ICMP***********************/



            /************************TCP**************************/
            table c2s_tcp_filter {
                key = {
                    hdr.ipv4.src_addr: lpm;
                    hdr.ipv4.dst_addr: ternary;
                }
                actions = {
                    notify_control_plane_tcp_c2s;
                    drop;
                }
                size = 1024;
            }

            table s2c_tcp_filter {
                key = {
                    hdr.ipv4.src_addr: exact;
                    hdr.ipv4.dst_addr: exact;
                    hdr.tcp.src_port: exact;
                    hdr.tcp.dst_port: exact;
                    // hdr.ipv4.dstAddr: ternary;
                }
                actions = {
                    meter;
                    tcp_s2c;
                    drop;
                }
                size = 1024;
                idle_timeout = true;
            }


            /***********************End TCP***********************/

            apply {
                // ig_dprsr_md.digest_type = 0;
                hdr.tcp.in_port = ig_intr_md.ingress_port;

                if(hdr.icmp.isValid()){
                    if (hdr.icmp.type == 8){
                        // ig_dprsr_md.digest_type = 0;
                        c2s_icmp_filter.apply();
                    }
                    else if (hdr.icmp.type == 0){
                        // ig_dprsr_md.digest_type = 1;
                        s2c_icmp_filter.apply();
                    }
                }  

                else if(hdr.tcp.isValid()){ 
                    if(hdr.tcp.flags == 2){
                        c2s_tcp_filter.apply();
                    }
                    else{
                        s2c_tcp_filter.apply();
                    }
                }

                if(ig_tm_md.ucast_egress_port != 192) {
			        ig_tm_md.ucast_egress_port=148; // just to go to egress
		        }
            }
        }

    /*********************  D E P A R S E R  ************************/
    control IngressDeparser(packet_out pkt,
        /* User */
        inout my_ingress_headers_t                       hdr,
        in    my_ingress_metadata_t                      meta,
        /* Intrinsic */
        in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
        {
            Digest<icmp_id_digest_t>() add_icmp_sc2_rule;
            Digest<icmp_id_digest_t>() remove_icmp_sc2_rule;
            Digest<tcp_digest_t>() add_tcp_sc2_rule;
            apply {

                if(ig_dprsr_md.digest_type == 0) {
                    add_icmp_sc2_rule.pack({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.icmp.identifier});
                } else if(ig_dprsr_md.digest_type == 1) {
                    remove_icmp_sc2_rule.pack({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.icmp.identifier});
                } else if(ig_dprsr_md.digest_type == 2) {
                    add_tcp_sc2_rule.pack({hdr.ipv4.src_addr, hdr.ipv4.dst_addr,hdr.tcp.src_port, hdr.tcp.dst_port});
                }
                pkt.emit(hdr);
            }
        }


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/
    struct my_egress_headers_t {
        ethernet_h   ethernet;
        ipv4_h       ipv4;
        tcp_h        tcp;
    }
    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/
    struct my_egress_metadata_t {
        bit<32> packet_hash;
        bit<32> packet_queue_delay;		
        bit<11> flow_id;
    }
    /***********************  P A R S E R  **************************/
    parser EgressParser(packet_in        pkt,
        /* User */
        out my_egress_headers_t          hdr,
        out my_egress_metadata_t         meta,
        /* Intrinsic */
        out egress_intrinsic_metadata_t  eg_intr_md)
        {
            /* This is a mandatory state, required by Tofino Architecture */
            state start {
                pkt.extract(eg_intr_md);
                transition parse_ethernet;
            }

            state parse_ethernet {
                pkt.extract(hdr.ethernet);
                transition select(hdr.ethernet.ether_type) {
                    ETHERTYPE_IPV4:  parse_ipv4;
                    default: accept;
                }
            }

            state parse_ipv4 {
                pkt.extract(hdr.ipv4);
                transition select(hdr.ipv4.protocol) {
                    6: parse_tcp;
                    default: accept;
                }
            }

            state parse_tcp {
                pkt.extract(hdr.tcp);
                transition accept;
            }
        }

    /***************** M A T C H - A C T I O N  *********************/
    control Egress(
        /* User */
        inout my_egress_headers_t                          hdr,
        inout my_egress_metadata_t                         meta,
        /* Intrinsic */
        in    egress_intrinsic_metadata_t                  eg_intr_md,
        in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
        inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
        inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
        {

            Hash<bit<11>>(HashAlgorithm_t.CRC16) hash;
                action apply_hash() {
                    meta.flow_id = hash.get({
                        hdr.ipv4.src_addr,
                        hdr.ipv4.dst_addr,
                        hdr.ipv4.protocol,
                        hdr.tcp.src_port,
                        hdr.tcp.dst_port
                    });
                }
                table calc_flow_id {
                    actions = {
                        apply_hash;
                    }
                    const default_action = apply_hash();
                }
                
                
                // ------------------------- QUEUE DELAY--------------------------------------
                // ---------------------------------------------------------------------------
                
                Hash<bit<32>>(HashAlgorithm_t.CRC32) packet_hash;
                action apply_packet_hash() {
                    meta.packet_hash = packet_hash.get({
                        meta.flow_id,
                        hdr.tcp.seq_no
                    });
                }
                table calc_packet_hash {
                    actions = {
                        apply_packet_hash;
                    }
                    const default_action = apply_packet_hash();
                }
                Register<bit<32>, bit<17>>(100000) packets_timestamp;
                RegisterAction<bit<32>, bit<17>, bit<32>>(packets_timestamp) update_packets_timestamp = {
                    void apply(inout bit<32> register_data) {
                            register_data = eg_prsr_md.global_tstamp[31:0];
                    }
                };
                action exec_update_packets_timestamp(){
                    update_packets_timestamp.execute(meta.packet_hash[16:0]);
                }
                RegisterAction<bit<32>, bit<17>, bit<32>>(packets_timestamp) calc_queue_delay_packet = {
                    void apply(inout bit<32> register_data, out bit<32> result) {
                        if(eg_prsr_md.global_tstamp[31:0] > register_data && eg_prsr_md.global_tstamp[31:0] - register_data < 50000000) {
                            result = eg_prsr_md.global_tstamp[31:0] - register_data;
                        } else {
                            result = 0;
                        }
                    }
                };
                action exec_calc_queue_delay_packet(){
                    meta.packet_queue_delay = calc_queue_delay_packet.execute(meta.packet_hash[16:0]);
                }     
                
                Register<bit<32>, _>(2048) queue_delays;
                RegisterAction<bit<32>, _, bit<32>>(queue_delays) update_queue_delays = {
                    void apply(inout bit<32> register_data) {
                        register_data = meta.packet_queue_delay;
                    }
                };
                action exec_update_queue_delays(){
                    update_queue_delays.execute(meta.flow_id);
                }

                Register<bit<32>, _>(2048) total_packets;
                RegisterAction<bit<32>, _, bit<32>>(total_packets) update_total_packets = {
                    void apply(inout bit<32> register_data) {
                        register_data = register_data + 1;
                    }
                };
                action exec_update_total_packets(){
                    update_total_packets.execute(meta.flow_id);
                }


                apply {
                    calc_flow_id.apply();
                    calc_packet_hash.apply();
                    exec_update_total_packets();
                    if (hdr.tcp.in_port == 148) {
                        exec_update_packets_timestamp();
                    }
                    else if(hdr.tcp.in_port == 140) {
                        exec_calc_queue_delay_packet();
                        if(meta.packet_queue_delay != 0) {
                            exec_update_queue_delays();
                        }
                    }
                    eg_dprsr_md.drop_ctl = 0;
                
                }
            }
        

    /*********************  D E P A R S E R  ************************/
    control EgressDeparser(packet_out pkt,
        /* User */
        inout my_egress_headers_t                       hdr,
        in my_egress_metadata_t                      meta,
        /* Intrinsic */
        in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
        {
            apply {
                pkt.emit(hdr);
            }
        }


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;



