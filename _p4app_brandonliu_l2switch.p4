/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

typedef bit<9>  port_t;
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> mcastGrp_t;

const port_t CPU_PORT           = 0x1;

const bit<16> ARP_OP_REQ        = 0x0001;
const bit<16> ARP_OP_REPLY      = 0x0002;

const bit<16> TYPE_ARP          = 0x0806;
const bit<16> TYPE_CPU_METADATA = 0x081b;
const bit<16> TYPE_IPV4         = 0x800;

const bit<8>  IP_PROT_UDP       = 0x11;
const bit<8>  IP_PROT_ICMP      = 0x1;
const bit<8>  IP_PROT_PWOSPF    = 0x59;

const bit<8>  PWOSPF_TYPE_HELLO = 0x01;
const bit<8>  PWOSPF_TYPE_LSU   = 0x04;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header cpu_metadata_t {
    bit<8> fromCpu;
    bit<16> origEtherType;
    bit<16> srcPort;
}

header arp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8> hwAddrLen;
    bit<8> protoAddrLen;
    bit<16> opcode;
    // assumes hardware type is ethernet and protocol is IP
    macAddr_t srcEth;
    ip4Addr_t srcIP;
    macAddr_t dstEth;
    ip4Addr_t dstIP;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen; // update length
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum; // Update this after cache hit
    ip4Addr_t srcAddr; // swap these after 
    ip4Addr_t dstAddr; //  cache hit
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header icmp_t {
    bit<16> typeCode;
    bit<16> hdrChecksum;
}

header pwospf_t {
    bit<8>  version;
    bit<8>  type;
    bit<16> length_;
    bit<32> routerID;
    bit<32> areaID;
    bit<16> checksum;
    bit<16> auType;
    bit<64> authentication;
}

header hello_t {
    ip4Addr_t netMask;
    bit<16>   helloint;
    bit<16>   padding;
}

struct headers {
    ethernet_t        ethernet;
    cpu_metadata_t    cpu_metadata;
    ipv4_t            ipv4;
    arp_t             arp;
    udp_t             udp;
    icmp_t            icmp;
    pwospf_t          pwospf;
    hello_t           hello;
}

struct metadata { }

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
            TYPE_ARP: parse_arp;
            TYPE_CPU_METADATA: parse_cpu_metadata;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROT_UDP: parse_udp;
            IP_PROT_ICMP: parse_icmp;
            IP_PROT_PWOSPF: parse_pwospf;
            default: accept;
        }
    }

    state parse_pwospf {
        packet.extract(hdr.pwospf);
        transition select(hdr.pwospf.type) {
            PWOSPF_TYPE_HELLO: parse_hello;
            // PWOSPF_TYPE_LSU: parse_lsu;
        }
    }

    state parse_hello {
        packet.extract(hdr.hello);
        transition accept;
    }

    // state parse_lsu {
    //     packet.extract(hdr.hello);
    //     transition accept;
    // }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

    state parse_cpu_metadata {
        packet.extract(hdr.cpu_metadata);
        transition select(hdr.cpu_metadata.origEtherType) {
            TYPE_ARP: parse_arp;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    counter(3, CounterType.packets) c;
    action tally_ipv4() {
        c.count((bit<32>) 0);
    } 
    action tally_arp() {
        c.count((bit<32>) 1);
    } 
    action tally_cpu() {
        c.count((bit<32>) 2);
    } 

    action drop() {
        mark_to_drop();
    }

    action set_egr(port_t port) {
        standard_metadata.egress_spec = port;
    }

    action set_mgid(mcastGrp_t mgid) {
        standard_metadata.mcast_grp = mgid;
    }

    action cpu_meta_encap() {
        hdr.cpu_metadata.setValid();
        hdr.cpu_metadata.origEtherType = hdr.ethernet.etherType;
        hdr.cpu_metadata.srcPort = (bit<16>)standard_metadata.ingress_port;
        hdr.ethernet.etherType = TYPE_CPU_METADATA;
    }

    action cpu_meta_decap() {
        hdr.ethernet.etherType = hdr.cpu_metadata.origEtherType;
        hdr.cpu_metadata.setInvalid();
    }

    action send_to_cpu() {
        cpu_meta_encap();
        standard_metadata.egress_spec = CPU_PORT;
        // tally_cpu();
    }

    action arp_reply(macAddr_t mac) {
        // Set ethernet source to the actual host Mac and dst to the original requester
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = mac;

        // Set src and dst IPs and Macs appropriately
        ip4Addr_t tmpSrcIP = hdr.arp.srcIP;
        macAddr_t tmpSrcEth = hdr.arp.srcEth;
        hdr.arp.srcEth = mac;
        hdr.arp.srcIP = hdr.arp.dstIP;
        hdr.arp.dstIP = tmpSrcIP;
        hdr.arp.dstEth = tmpSrcEth;

        // Change ARP header from request to reply
        hdr.arp.opcode = ARP_OP_REPLY;

        // Bounce the packet back out on the physical port that it arrive into the switch on
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    action ipv4_route(egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table fwd_l2 {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            set_egr;
            set_mgid;
            send_to_cpu;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_route;
            ipv4_forward;
            send_to_cpu;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = send_to_cpu();
    }

    table arp_table {
        key = {
            hdr.arp.dstIP: exact;
        }
        actions = {
            send_to_cpu;
            arp_reply;
            drop;
            NoAction;
        }
        size = 64;
        default_action = send_to_cpu();
    }

    table one_hop {
        key = {
            hdr.ipv4.srcAddr: exact;
        }
        actions = {
            set_egr;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        // first apply counters
        if(hdr.ipv4.isValid()) tally_ipv4();
        if(hdr.arp.isValid())  tally_arp();
        if(standard_metadata.ingress_port == CPU_PORT)
            cpu_meta_decap();
        if(hdr.pwospf.isValid() && standard_metadata.ingress_port == CPU_PORT) {
            one_hop.apply();
        }
        else if(hdr.pwospf.isValid()) {
            send_to_cpu();
        }
        else if(hdr.arp.isValid() && hdr.arp.opcode == ARP_OP_REQ && standard_metadata.ingress_port != CPU_PORT) {
            arp_table.apply();
        }
        else if(hdr.arp.isValid() && standard_metadata.ingress_port != CPU_PORT) {
            send_to_cpu();
        }
        else if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
        else if (hdr.ethernet.isValid() ) {// && !hdr.ipv4.isValid()) {
            fwd_l2.apply();
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

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

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu_metadata);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
        packet.emit(hdr.pwospf);
        packet.emit(hdr.hello);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
