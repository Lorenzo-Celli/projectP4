/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_MYTUNNEL = 0x1212;
const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header tunnel_t {
    bit<16> proto_id;
    bit<16> t_id;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

struct metadata {
    /* empty */
}

// NOTE: Added new header type to headers struct
struct headers {
    ethernet_t ethernet;
    tunnel_t tunnel;
    ipv4_t ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_MYTUNNEL : parse_tunnel;
            TYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }

    state parse_tunnel {
        packet.extract(hdr.tunnel);
        transition select(hdr.tunnel.proto_id){
            TYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }


}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        log_msg("pachetto droppetto");
        mark_to_drop(standard_metadata);
    }

    /*
    action ipv4_forward(bit<48> dstAddr, bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 5;
    }*/

    action ipv4_encap(bit<16> t_id, bit<9> port, bit<48> dstAddr){
        log_msg("test");
        hdr.tunnel.setValid();
        
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 5;

        hdr.tunnel.t_id = t_id; //BB
        hdr.tunnel.proto_id = TYPE_IPV4;
        standard_metadata.egress_spec = port;
    }

    table ipv4_encap_lpm {
        key = {

            hdr.ipv4.dstAddr: lpm;
            //256
            hdr.ipv4.diffserv: ternary;
            //hdr.ipv4.ttl : exact;
        }
        actions = {
            // ipv4_forward;
            ipv4_encap;
            drop;
            NoAction;
        }
        size = 1024;
        // default_action = drop();
    }

    table ipv4_srv_encap_lpm {
        key = {
            hdr.ipv4.srcAddr: lpm;
        }
        actions = {
            ipv4_encap;
            drop;
            NoAction;
        }
        size = 1024;
        // default_action = NoAction();
    }

    // TODO: declare a new action: tunnel_forward(egressSpec_t port, bit<16> tid)
    action tunnel_forward(egressSpec_t port){
        // hdr.tunnel.t_id = tid;
        standard_metadata.egress_spec = port;
    }

    table tunnel_exact{
        key = {
            hdr.tunnel.t_id : exact;
        }
        actions = {
            tunnel_forward;
            // tunnel_pop;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    // TODO: also remember to add table entries!


    apply {
        if (hdr.ipv4.isValid() && !hdr.tunnel.isValid()) {
            ipv4_srv_encap_lpm.apply();
            ipv4_encap_lpm.apply();
        }

        if (hdr.tunnel.isValid()){
            //tunnel_exact.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.tunnel);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
