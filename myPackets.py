from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether, ARP
from scapy.fields import ByteField, ShortField, IntField, LongField, FieldLenField, PacketListField, IPField

IP_PROT_PWOSPF = 0x59
PWOSPF_TYPE_HELLO = 0x01
PWOSPF_TYPE_LSU = 0x04

class PWOSPF(Packet):
    name = "PWOSPF"
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

bind_layers(IP, PWOSPF, proto=IP_PROT_PWOSPF)

class Hello(Packet):
    name = "Hello"
    fields_desc = [
        IPField("netMask", None),
        ShortField("helloint", None),
        ShortField("padding", 0)
    ]

bind_layers(PWOSPF, Hello, type=PWOSPF_TYPE_HELLO)

class LSA(Packet):
    name = "LSA"
    fields_desc = [
        IPField("subnet", None),
        IPField("mask", None),
        IPField("routerID", None),
    ]
    def extract_padding(self, p):
        return "",p

class LSU(Packet):
    name = "LSU"
    fields_desc = [
        ShortField("sequence", None),
        ShortField("ttl", 64),
        FieldLenField("numAds", None, fmt="I", count_of="lsaList"),
        PacketListField("lsaList", None, LSA, count_from = lambda pkt: pkt.numAds)
    ]

bind_layers(PWOSPF, LSU, type=PWOSPF_TYPE_LSU)