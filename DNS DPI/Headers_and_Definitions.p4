/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
const bit<16> ETHERTYPE_TPID = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<8> TYPE_ICMP = 0x01;
const bit<8> TYPE_TCP= 0x06;
const bit<8> TYPE_UDP= 0x11;
const bit<16> ETHERTYPE_IPV6 = 0x86dd;
const bit<16> DNS_QUERY      = 0x0120;
const bit<16> DNS_RESPONSE   = 0x8180;
typedef bit<32> value_t;


/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress cn differ */

/* Standard ethernet header */
header ethernet_h {
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
}

header vlan_tag_h {
    bit<3>   pcp;
    bit<1>   cfi;
    bit<12>  vid;
    bit<16>  ether_type;
}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

header ipv6_h {
	bit<4> version;
	bit<8> trafficClass;
	bit<20> flowLabel;
	bit<16> payloadLen;
	bit<8> nextHdr;
	bit<8> hopLimit;
	bit<128> src_addr;
	bit<128> dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
	bit<9> in_port;
	bit<7> dummy;
}

header udp_h {
	bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}

header icmp_t {
    bit<8> type;
    bit<8> code;
    bit<16> hdrChecksum;
    bit<16> identifier;
    bit<16> seqNum;
}


header rtp_h {
    bit<2>   version;
    bit<1>   padding;
    bit<1>   extension;
    bit<4>   CSRC_count;
    bit<1>   marker;
    bit<7>   payload_type;
    bit<16>  sequence_number;
    bit<32>  timestamp;
    bit<32>  SSRC;
}

header dns_h {
    bit<16> id;
    bit<16> flags;
}