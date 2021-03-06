from threading import Thread, Event
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP, Raw
from async_sniff import sniff
from cpu_metadata import CPUMetadata
import time
from peewee import PWRouter, PWInterface
from hello_protocol import HelloProtocol
from lsu_protocol import LSUProtocol
from myPackets import Hello, PWOSPF, LSU, IP_PROT_PWOSPF
from timeout_watcher import TimeoutWatcher

ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002
PWOSPF_TYPE_HELLO = 0x01

class MacLearningController(Thread):
    def __init__(self, sw, id, start_wait=0.3):
        super(MacLearningController, self).__init__() # Initializes Thread object
        self.sw = sw
        self.start_wait = start_wait # time to wait for the controller to be listenning
        self.iface = sw.intfs[1].name
        self.port_for_mac = {}
        self.stop_event = Event() # Thread API thing, do this event when the thread is stopped?
        self.arpTable = {} # key = ip, value = mac
        self.router = PWRouter(self.sw,id,1)
        self.helloProtocol = HelloProtocol(self.sw, self.router, self.iface)
        self.helloProtocol.start()
        self.lsuProtocol = LSUProtocol(self.sw, self.router, self.iface)
        self.lastLSUSequence = -1
        self.lastLSUPacket = None
        self.timeoutWatcher = TimeoutWatcher(self.router)
        self.timeoutWatcher.start()

    def addMacAddr(self, mac, port):
        # Don't re-add the mac-port mapping if we already have it:
        if mac in self.port_for_mac: return

        self.sw.insertTableEntry(table_name='MyIngress.fwd_l2',
                match_fields={'hdr.ethernet.dstAddr': [mac]},
                action_name='MyIngress.set_egr',
                action_params={'port': port})
        self.port_for_mac[mac] = port

    def mask24(self, ipAddr):
        return ipAddr[:-1] + "0"

    def addArpMappingAndHostRules(self, pkt):
        ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc
        if ip in self.arpTable: return
        self.sw.insertTableEntry(table_name='MyIngress.arp_table',
                            match_fields={'hdr.arp.dstIP': [ip, 32]},
                            action_name='MyIngress.arp_reply',
                            action_params={'mac': mac})
        self.sw.insertTableEntry(table_name='MyIngress.ipv4_lpm',
                            match_fields={'hdr.ipv4.dstAddr': [ip, 32]},
                            action_name='MyIngress.ipv4_forward',
                            action_params={'dstAddr': mac, 'port': pkt[CPUMetadata].srcPort})
        self.arpTable[ip] = mac

    def handleArpReply(self, pkt):
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.addArpMappingAndHostRules(pkt)
        self.send(pkt)

    def handleArpRequest(self, pkt):
        # pkt.show2()
        # check if ip src is not in the subnet
        # if self.mask24(pkt[ARP].psrc) != self.mask24(pkt[ARP].pdst):
        if self.mask24(pkt[ARP].psrc) != self.mask24(self.router.routerID):
            # send arp reply with current switch mac
            print("NOT IN NETWORK")
            return
            # pkt[Ether].dst = pkt[Ether].src
            # pkt[Ether].src = self.sw.MAC() # set source to this switch's mac (Bogus? None)
        
            # tmpSrcIP = pkt[ARP].psrc
            # tmpSrcEth = pkt[ARP].hwsrc
            # pkt[ARP].hwsrc = self.sw.MAC() # set the mapping to this external IP to be the switch's mac
            # pkt[ARP].psrc = pkt[ARP].pdst
            # pkt[ARP].pdst = tmpSrcIP
            # pkt[ARP].hwdst = tmpSrcEth
            # pkt[ARP].op = ARP_OP_REPLY
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.addArpMappingAndHostRules(pkt)
        self.send(pkt) # otherwise multicast just send to the multicast address

    def handleHello(self, pkt, origPkt):
        # print("Controller received hello packet!")
        # check if sending and recieving interface netMask and helloint fields match
        receivingIntf = self.router.interfaces[origPkt[CPUMetadata].srcPort]
        if pkt[Hello].netMask != receivingIntf.netMask or pkt[Hello].helloint != receivingIntf.helloint:
            print("Drop packet", pkt[Hello].netMask, receivingIntf.netMask)
            print(pkt[Hello].helloint, receivingIntf.helloint)
            return
        sendingIntfIP = origPkt[IP].src
        sendingRouterID = pkt[PWOSPF].routerID
        if sendingIntfIP not in receivingIntf.neighbors:
            # The receiving interface has a neighbor of interfaceIP and the last time recieved hello and routerId are the values
            receivingIntf.neighbors[sendingIntfIP] = [sendingRouterID, time.time(),] # Neighbor ID and last time updated
            print("Router " + str(self.router.routerID) + " added neighbor: (" + str(sendingRouterID) + ", " + str(sendingIntfIP)+")")
            self.router.topology.graph[self.router.routerID].append(sendingRouterID) # Add the sending router as a neighbor to my topo
        else:
            receivingIntf.neighbors[sendingIntfIP][1] = time.time()
        
    
    def handleLSU(self, pkt):
        # If the LSU was originally generated by the incoming router, the packet is dropped. ???
        # If the sequence number matches that of the last packet received from the sending host, the packet is dropped.
        if pkt[LSU].sequence == self.lastLSUSequence:
            print("Last LSU sequence number is the same as the current, dropping packet.")
            return
        # If the packet contents are equivalent to the contents of the packet last received from the sending host, ignore
        if pkt[LSU] == self.lastLSUPacket:
            print("LSU packet is the same as the last one, dropping packet.")
            return
        # Entries can only be added, so add LSA data and then calculate best ports/paths
        myTopoData = self.router.topology
        # print("BRANDON: Show packet before looping through LSAs")
        # pkt.show2()
        for lsa in pkt[LSU].lsaList:
            # print("BRANDON: entered lsa Loop")
            if lsa.subnet not in myTopoData.subnetsAtRouter[pkt[PWOSPF].routerID]:
                myTopoData.subnetsAtRouter[pkt[PWOSPF].routerID].append(lsa.subnet)
        # print(myTopoData.subnetsAtRouter)    
        myTopoData.updateBestPorts()
        myTopoData.installForwardingRules()

    def handlePkt(self, pkt):
        
        assert CPUMetadata in pkt, "Should only receive packets from switch with special header"
        # Ignore packets that the CPU sends:
        if pkt[CPUMetadata].fromCpu == 1: return
        if ARP in pkt:
            # print("BRANDON: ARP")
            if pkt[ARP].op == ARP_OP_REQ:
                self.handleArpRequest(pkt)
            elif pkt[ARP].op == ARP_OP_REPLY:
                self.handleArpReply(pkt)
            return
        if pkt[IP].proto == IP_PROT_PWOSPF:
            try:
                pwospf_pkt = PWOSPF(pkt[Raw])
            except Exception:
                print('Brandon %s cannot parse this PWOSPF packet correctly\n' % self.sw.name)
                return
            if Hello in pwospf_pkt:
                self.handleHello(pwospf_pkt, pkt)
            elif LSU in pwospf_pkt:
                self.handleLSU(pwospf_pkt)
            else:
                print("Invalid OSPF packet structure (no Hello or LSU)")
                return
        

    def send(self, *args, **override_kwargs):
        pkt = args[0]
        assert CPUMetadata in pkt, "Controller must send packets with special header"
        pkt[CPUMetadata].fromCpu = 1
        kwargs = dict(iface=self.iface, verbose=False)
        kwargs.update(override_kwargs)
        sendp(*args, **kwargs)

    def run(self): # sniff has a while True loop
        sniff(iface=self.iface, prn=self.handlePkt, stop_event=self.stop_event)

    def start(self, *args, **kwargs):
        super(MacLearningController, self).start(*args, **kwargs)
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(MacLearningController, self).join(*args, **kwargs)
    