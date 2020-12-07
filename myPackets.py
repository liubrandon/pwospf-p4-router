from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether, ARP
from scapy.fields import ByteField, ShortField, IntField, LongField, FieldLenField, PacketListField, IPField

IP_PROT_PWOSPF = 0x59
PWOSPF_TYPE_HELLO = 0x01
PWOSPF_TYPE_LSU = 0x04

class PWOSPF(Packet):
    name = "OSPF"
    fields_desc = [
        ByteField("version", 2),
        ByteField("type", None),
        ShortField("length", None),
        IPField("routerID", None),
        IntField("areaID", None),
        ShortField("checksum", 0),
        ShortField("auType", 0),
        LongField("authentication", 0)
    ]


class Hello(Packet):
    name = "OSPF_hello"
    fields_desc = [
        IPField("netMask", None),
        ShortField("helloint", None),
        ShortField("padding", 0)
    ]


class LSA(Packet):
    # name = "LSA"
    fields_desc = [
        IPField("subnet", None),
        IPField("mask", None),
        IPField("routerID", None),
    ]
    def extract_padding(self, p):
        return "",p

class LSU(Packet):
    name = "OSPF_LSU"
    fields_desc = [
        ShortField("sequence", None),
        ShortField("ttl", 64),
        FieldLenField("numAds", 0, count_of="lsaList"),
        PacketListField("lsaList", [], LSA, count_from = lambda pkt: pkt.numAds)
    ]

# bind_layers(IP, PWOSPF, proto=IP_PROT_PWOSPF)
bind_layers(PWOSPF, Hello, type=PWOSPF_TYPE_HELLO)
bind_layers(PWOSPF, LSU, type=PWOSPF_TYPE_LSU)