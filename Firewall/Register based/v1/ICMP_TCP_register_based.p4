/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>
#include "Headers_and_Definitions.p4"

struct icmp_digest_t {
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
        bit<11> rev_flow_id;
        bit<16> icmp_id;
        bit<16> allow_REPLY;
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
                        hdr.ipv4.protocol

                                        });
                                    }

                table calc_flow_id {
                    actions = {
                        apply_hash;
                    }
                    const default_action = apply_hash();
                }
                Hash<bit<11>>(HashAlgorithm_t.CRC16) rev_hash;
                action apply_rev_hash() {
                    meta.rev_flow_id = rev_hash.get({
                        hdr.ipv4.dst_addr,
                        hdr.ipv4.src_addr,
                        hdr.ipv4.protocol
                        
                                        });
                                    }

                table calc_rev_flow_id {
                    actions = {
                        apply_rev_hash;
                    }
                    const default_action = apply_rev_hash();
                }
            /*********************End Hashing**********************/

            /***********************Actions************************/
                action drop() {
                    ig_dprsr_md.drop_ctl = 0x1; // Drop packet.
                } 



            /*********************End Actions***********************/


            /************************ICMP**************************/
            table c2s_icmp_filter {
                key = {
                    hdr.ipv4.src_addr: lpm;
                    hdr.ipv4.dst_addr: ternary;
                }
                actions = {
                    NoAction;
                }
                size = 1024;
            }
            
            Register<bit<16>, _>(2048) icmp_id;

            RegisterAction<bit<16>, _, bit<16>>(icmp_id) update_icmp_id = {
                void apply(inout bit<16> register_data) {
                    register_data = hdr.icmp.identifier;
                }
            };
            action exec_update_icmp_id(){
                update_icmp_id.execute(meta.flow_id);
            }

            RegisterAction<bit<16>, _, bit<16>>(icmp_id) check_icmp_id = {
                void apply(inout bit<16> register_data, out bit<16> result) {
                    if(register_data == hdr.icmp.identifier){
                        result =1;
                        register_data = 0;
                    }
                    else{
                        result = 0;
                    }
                }
            };
            action exec_check_icmp_id(){
                meta.allow_REPLY = check_icmp_id.execute(meta.rev_flow_id);
            } 


            /***********************End ICMP***********************/



            /************************TCP**************************/
            table c2s_tcp_filter {
                key = {
                    hdr.ipv4.src_addr: lpm;
                    hdr.ipv4.dst_addr: ternary;
                }
                actions = {
                    NoAction;
                }
                size = 1024;
            }

            Register<bit<16>, _>(2048) tcp_dst_port;
            RegisterAction<bit<16>, _, bit<16>>(tcp_dst_port) update_tcp_dst_port = {
                void apply(inout bit<16> register_data) {
                    register_data = hdr.tcp.dst_port;
                }
            };
            action exec_update_tcp_dst_port(){
                update_tcp_dst_port.execute(meta.flow_id);
            }

            RegisterAction<bit<16>, _, bit<16>>(tcp_dst_port) check_tcp_dst_port = {
                void apply(inout bit<16> register_data, out bit<16> result) {
                    if(register_data == hdr.tcp.src_port){
                        result =1;
                    }
                    else{
                        result = 0;
                    }
                }
            };
            action exec_check_tcp_port(){
                meta.allow_REPLY = (bit<16>)check_tcp_dst_port.execute(meta.rev_flow_id);
            }


            /***********************End TCP***********************/

            apply {
                // ig_dprsr_md.digest_type = 0;
                hdr.tcp.in_port = ig_intr_md.ingress_port;
                calc_flow_id.apply();
                calc_rev_flow_id.apply();
                if(hdr.icmp.isValid()){
                    if (hdr.icmp.type == 8){ // ECHO packet
                        if(c2s_icmp_filter.apply().hit){
                            exec_update_icmp_id();
                            ig_dprsr_md.digest_type = 0;
                        }
                    }
                    else if (hdr.icmp.type == 0){ // REPLY packet
                        // ig_dprsr_md.digest_type = 0;
                        exec_check_icmp_id();
                        if(meta.allow_REPLY == 1){
                            ig_dprsr_md.digest_type = 0;
                        }
                    }
                }  

                else if(hdr.tcp.isValid()){ 
                    if(c2s_tcp_filter.apply().hit){
                        if(hdr.tcp.flags == 2){
                            exec_update_tcp_dst_port();
                            ig_dprsr_md.digest_type = 1;
                        }        
                    }

                    else{
                        exec_check_tcp_port();
                        if(meta.allow_REPLY == 1){
                            ig_dprsr_md.digest_type = 1;
                        }
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
            Digest<icmp_digest_t>() icmp_accepted;
            Digest<tcp_digest_t>() tcp_accepted;

            apply {
                if(ig_dprsr_md.digest_type == 0) {
                        icmp_accepted.pack({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.icmp.identifier});
                    }
                else if(ig_dprsr_md.digest_type == 1) {
                    tcp_accepted.pack({hdr.ipv4.src_addr, hdr.ipv4.dst_addr,hdr.tcp.src_port, hdr.tcp.dst_port});
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



