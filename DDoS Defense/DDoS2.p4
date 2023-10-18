/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/

#include "Headers_and_Definitions.p4"

#define TIME_THRESHOLD  2
#define NUM_SYN_PACKETS 2
#define IP_PROTOCOLS_TCP 6
#define IP_PROTOCOLS_UDP 17

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress cn differ */

struct flood_digest_t {
    bit<32> syn_counts;
}

struct flood_icmp_digest_t {
    bit<32> icmp_counts;
} 

struct dns_amplification_digest_t {
    bit<32> dns_counts;
    bit<32> ip_address; 
    bit<32> query_total; 
    bit<32> response_total; 
}  


/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

        struct my_ingress_headers_t {
            ethernet_h   ethernet;
            ipv4_h       ipv4;
            ipv6_h       ipv6;
            tcp_h        tcp;
            udp_h        udp;
            icmp_t       icmp;
            //dns_h        dns;
        }

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/
        struct my_ingress_metadata_t {
            bit<32> syn_counts;
            bit<32> icmp_counts;
            bit<32> dns_counts;   
            bit<16> flow_hash;
            bit<32> addr;
            bit<32> query_total;
            bit<32> response_total;
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
                    ETHERTYPE_IPV6 : parse_ipv6;
                    default: accept;
                }
            }

            state parse_ipv4 {
                pkt.extract(hdr.ipv4);
                transition select(hdr.ipv4.protocol) {
                    6: parse_tcp;
                    0x11: parse_udp;
                    default: accept;
                }
            }
            
            state parse_ipv6 {
                pkt.extract(hdr.ipv6);
                transition select(hdr.ipv6.nextHdr) {
                    IP_PROTOCOLS_TCP : parse_tcp;
                    IP_PROTOCOLS_UDP : parse_udp;
                }
            }

            state parse_tcp {
                pkt.extract(hdr.tcp);
                transition accept;
            }

            state parse_udp {
                pkt.extract(hdr.udp);
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

            bit<1> time_period_expired;
            bit<1> time_period_expired_icmp;
            bit<1> time_period_expired_dns;
            bit<32> tmp;

        /*************************HASHING******************************/
            Hash<bit<16>>(HashAlgorithm_t.CRC16) flow_hash_src;
            Hash<bit<16>>(HashAlgorithm_t.CRC16) flow_hash_dst;

            action apply_flow_hash_src() {
                meta.flow_hash = flow_hash_src.get({
                    hdr.ipv4.src_addr
                });
            }
            table calc_flow_hash_src {
                actions = {
                    apply_flow_hash_src;
                }
                const default_action = apply_flow_hash_src();
            }

            action apply_flow_hash_dst() {
                meta.flow_hash = flow_hash_dst.get({
                    hdr.ipv4.dst_addr
                });	
            }
            table calc_flow_hash_dst {
                actions = {
                    apply_flow_hash_dst;
                }
                const default_action = apply_flow_hash_dst();
            }
        
        /***********************END HASHING****************************/

            Register<bit<32>, bit<16>>(65535) syn_counts;
            RegisterAction<bit<32>, bit<16>, bit<32>>(syn_counts) update_syn_counts = {
                void apply(inout bit<32> register_data, out bit<32> result) {
                    if(time_period_expired == 0) {
                        register_data = register_data + 1;
                    } else {
                        result 	      = register_data + 1;
                        register_data = 0;
                    }
                        
                }
            };
            action apply_update_syn_counts() {
                meta.syn_counts = update_syn_counts.execute(meta.flow_hash);
            }
                        // For SYN Reporting duration
            Register<bit<16>, bit<16>>(65535) last_period_timestamp;
            RegisterAction<bit<16>, bit<16>, bit<1>>(last_period_timestamp) 
                update_last_report_timestamp = {
                    void apply(inout bit<16> register_data, out bit<1> result) {
                        if (register_data == 0) {
                            register_data = ig_intr_md.ingress_mac_tstamp[44:29];
                        } else {
                            bit<16> tmp; 
                            tmp = ig_intr_md.ingress_mac_tstamp[44:29] - register_data;
                            if(tmp > 1) {
                                register_data = ig_intr_md.ingress_mac_tstamp[44:29];
                                result = 1;
                            } else {
                                result = 0;
                            }
                        }
                    }
            };
            action apply_update_last_report_timestamp() {
                time_period_expired = update_last_report_timestamp.execute(meta.flow_hash);
            }
        /**************************ICMP**********************************/
            Register<bit<32>, bit<16>>(65535) icmp_counts;
            RegisterAction<bit<32>, bit<16>, bit<32>>(icmp_counts) update_icmp_counts = {
                void apply(inout bit<32> register_data, out bit<32> result) {
                    if(time_period_expired_icmp == 0) {
                        register_data = register_data + 1;
                    } else {
                        result 	      = register_data + 1;
                        register_data = 0;
                    }
                        
                }
            };
            action apply_update_icmp_counts() {
                meta.icmp_counts = update_icmp_counts.execute(meta.flow_hash);
            }

            Register<bit<16>, bit<16>>(65535) last_period_timestamp_icmp; // For ICMP Reporting duration
            RegisterAction<bit<16>, bit<16>, bit<1>>(last_period_timestamp_icmp) update_last_period_timestamp_icmp = {
                void apply(inout bit<16> register_data, out bit<1> result) {
                    if (register_data == 0) {
                        register_data = ig_intr_md.ingress_mac_tstamp[44:29];
                    } else {
                        bit<16> tmp; 
                        tmp = ig_intr_md.ingress_mac_tstamp[44:29] - register_data;
                        if(tmp > 1) {
                            register_data = ig_intr_md.ingress_mac_tstamp[44:29];
                            result = 1;
                        } else {
                            result = 0;
                        }
                    }

                }
            };
            action apply_update_last_period_timestamp_icmp() {
                time_period_expired_icmp = update_last_period_timestamp_icmp.execute(meta.flow_hash);
            }
        /*************************END ICMP******************************/

            Register<bit<16>, bit<16>>(65535) last_period_timestamp_dns; // For DNS reporting duration
            RegisterAction<bit<16>, bit<16>, bit<1>>(last_period_timestamp_dns) update_last_report_timestamp_dns = {
                void apply(inout bit<16> register_data, out bit<1> result) {
                    if (register_data == 0) {
                        register_data = ig_intr_md.ingress_mac_tstamp[44:29];
                    } else {
                        bit<16> tmp2; 
                        tmp2 = ig_intr_md.ingress_mac_tstamp[44:29] - register_data;
                        if(tmp2 > TIME_THRESHOLD) {
                            register_data = ig_intr_md.ingress_mac_tstamp[44:29];
                            result = 1;
                        } else {
                            result = 0;
                        }
                    }

                }
            };
            action apply_update_last_report_timestamp_dns() {
                time_period_expired_dns = update_last_report_timestamp_dns.execute(meta.flow_hash);
            }


            Register<bit<32>, bit<32>>(65535) dns_counts;
            RegisterAction<bit<32>, bit<16>, bit<32>>(dns_counts) decrement_dns_counts = {
                void apply(inout bit<32> register_data, out bit<32> result) {
                    if(time_period_expired_dns == 0) {
                        register_data = register_data - 1;					
                    } else {
                        result 	      = register_data - 1;
                        register_data = 0;
                    }
                        
                }
            };
            action apply_decrement_dns_counts() {
                meta.dns_counts = decrement_dns_counts.execute(meta.flow_hash);
            }
            RegisterAction<bit<32>, bit<16>, bit<32>>(dns_counts) increment_dns_counts = {
                void apply(inout bit<32> register_data, out bit<32> result) {
                    if(time_period_expired_dns == 0) {
                        register_data = register_data + 1;
                    } else {
                        result 	      = register_data + 1;
                        register_data = 0;
                    }
                        
                }
            };
            action apply_increment_dns_counts() {
                meta.dns_counts = increment_dns_counts.execute(meta.flow_hash);
            }
            
            
            Register<bit<32>, bit<32>>(65535) query_total;
            RegisterAction<bit<32>, bit<16>, bit<32>>(query_total) update_query_total = {
                void apply(inout bit<32> register_data, out bit<32> result) {
                    if(time_period_expired_dns == 0) {
                        register_data = register_data + (bit<32>)hdr.ipv4.total_len;
                    } else {
                        result 	      = register_data + (bit<32>)hdr.ipv4.total_len;
                        register_data = 0;
                    }
                        
                }
            };
            action apply_update_query_total() {
                meta.query_total = update_query_total.execute(meta.flow_hash);
            }
            RegisterAction<bit<32>, bit<16>, bit<32>>(query_total) read_query_total = {
                void apply(inout bit<32> register_data, out bit<32> result) {
                        
                        result = register_data;  
                        if(time_period_expired_dns == 1) {
                            register_data = 0;
                        }
                }
            };
            action apply_read_query_total() {
                meta.query_total = read_query_total.execute(meta.flow_hash);
            }
            
            
            Register<bit<32>, bit<32>>(65535) response_total;
            RegisterAction<bit<32>, bit<16>, bit<32>>(response_total) update_response_total = {
                void apply(inout bit<32> register_data, out bit<32> result) {
                    if(time_period_expired_dns == 0) {
                        register_data = register_data + (bit<32>)hdr.ipv4.total_len;
                    } else {
                        result 	      = register_data + (bit<32>)hdr.ipv4.total_len;
                        register_data = 0;
                    }
                        
                }
            };
            action apply_update_response_total() {
                meta.response_total = update_response_total.execute(meta.flow_hash);
            }
            RegisterAction<bit<32>, bit<16>, bit<32>>(response_total) read_response_total = {
                void apply(inout bit<32> register_data, out bit<32> result) {
                        
                        result = register_data;  
                        if(time_period_expired_dns == 1) {
                            register_data = 0;
                        }
                }
            };
            action apply_read_response_total() {
                meta.response_total = read_response_total.execute(meta.flow_hash);
            }


            apply {
                        
                if(hdr.ipv4.isValid()) {
                    calc_flow_hash_src.apply();
                    if(hdr.tcp.isValid()) {
                        if(hdr.tcp.flags == 2) { //SYN FLAG
                            apply_update_last_report_timestamp();
                            apply_update_syn_counts();
                            if(time_period_expired == 1) {
                                ig_dprsr_md.digest_type = 0;
                            }
                        }
                    }
                    else if (hdr.icmp.isValid()){
                        if (hdr.icmp.type == 8){ // ECHO packet
                            apply_update_last_period_timestamp_icmp();
                            apply_update_icmp_counts();
                            if(time_period_expired_icmp == 1) {
                                ig_dprsr_md.digest_type = 2;
                            }
                        }
                    }
                    else if (hdr.udp.isValid()) {
                    if(hdr.udp.dst_port == 53 ) { // DNS_QUERY
                            calc_flow_hash_dst.apply();
                            apply_update_last_report_timestamp_dns();
                            apply_decrement_dns_counts();
                            meta.addr = hdr.ipv4.dst_addr;
                            apply_update_query_total();
                            apply_read_response_total();
                            
                        } else if (hdr.udp.src_port == 53) { // DNS_RESPONSE
                            apply_update_last_report_timestamp_dns();
                            apply_increment_dns_counts();
                            meta.addr = hdr.ipv4.src_addr;
                            apply_update_response_total();
                            apply_read_query_total();
                            if(time_period_expired_dns == 1) {
                                ig_dprsr_md.digest_type = 1;
                            }
                        }
                    }


                    // Forwarding:
                    if(ig_intr_md.ingress_port == 0) {
                        ig_tm_md.ucast_egress_port = 1;
                    } else {
                        ig_tm_md.ucast_egress_port = 0;
                    }
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
    Digest<flood_digest_t>() syn_flood; 
    Digest<flood_digest_t>() icmp_flood;
    Digest<dns_amplification_digest_t>() dns_amplification; 

    apply {
        if(ig_dprsr_md.digest_type == 0) {
            syn_flood.pack({meta.syn_counts});
        } else if(ig_dprsr_md.digest_type == 1) {
            dns_amplification.pack({meta.dns_counts, meta.addr, meta.query_total, meta.response_total});
        }
        else if(ig_dprsr_md.digest_type == 2) {
            icmp_flood.pack({meta.icmp_counts});
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
	apply {
	
    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in my_egress_metadata_t                         meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
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
