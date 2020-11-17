from threading import Thread, Event
import time
from myPackets import PWOSPF, LSU, LSA
from scapy.all import Packet, Ether, IP, ARP
from scapy.all import sendp
from peewee import PWRouter, PWInterface
from cpu_metadata import CPUMetadata
import copy
IP_PROT_PWOSPF = 89
PWOSPF_TYPE_LSU = 4
NETMASK = "255.255.255.0" #0xffffff00
class LSUProtocol(Thread):
    def __init__(self, sw, router, iface, start_wait=.3):
        super(LSUProtocol, self).__init__() # Initializes Thread object
        self.stop_event = Event() # Thread API thing, do this event when the thread is stopped?
        self.start_wait = start_wait # time to wait for the controller to be listenning
        self.router = router
        self.iface = iface
        self.sw = sw
        self.senderThreads = [None, None]
        # Create a LSUSender thread to send lsu packets out of each interface (port)
        # Skip 1 as it is the CPU
        for i in range(2,len(router.interfaces)):
            self.senderThreads.append(LSUSender(router, i, self.router.lsuint, iface))
        for i in range(2,len(router.interfaces)):
            self.senderThreads[i].start()

    def run(self):
        pass

    def start(self, *args, **kwargs):
        super(LSUProtocol, self).start(*args, **kwargs)
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(LSUProtocol, self).join(*args, **kwargs)
    
class LSUSender(Thread):
    def __init__(self, router, egressPort, lsuint, iface, start_wait=0.3):
        super(LSUSender, self).__init__() # Initializes Thread object
        self.stop_event = Event() # Thread API thing, do this event when the thread is stopped?
        self.start_wait = start_wait # time to wait for the controller to be listenning
        self.egressPort = egressPort
        self.router = router
        self.lsuint = lsuint
        self.iface = iface
        self.lsuPackets = []
        self.sequence = 0
        self.ttl = 64
    
    def generateLSAList(self):
        lsaList = []
        for i in range(2, len(self.router.interfaces)):
            lsaLayer = LSA(subnet=self.router.routerID,mask=self.router.interfaces[i].netMask,routerID=self.router.routerID)
            lsaList.append(lsaLayer)
        if not lsaList:
            print("NO LSA PACKETS")
        return copy.deepcopy(lsaList) if lsaList else None

    def generateLSUPackets(self):
        self.lsuPackets = []
        for dstIntfIP in self.router.interfaces[self.egressPort].neighbors:
            etherLayer   = Ether()
            cpuLayer     = CPUMetadata(fromCpu=1,origEtherType=0x800)
            ipLayer      = IP(src=self.router.interfaces[self.egressPort].ipAddr,dst=dstIntfIP,proto=IP_PROT_PWOSPF)
            pwospfLayer  = PWOSPF(type=PWOSPF_TYPE_LSU,length=32,routerID=self.router.routerID,areaID=0,checksum=0)
            lsuLayer     = LSU(sequence=self.sequence,ttl=self.ttl,lsaList=self.generateLSAList())
            lsuPacket   = etherLayer/cpuLayer/ipLayer/pwospfLayer/lsuLayer
            self.lsuPackets.append(lsuPacket)
        self.ttl -= 1
        self.sequence += 1
        
    def run(self): # sniff has a while True loop
        while True:
            self.generateLSUPackets()
            for lsuPacket in self.lsuPackets:
                self.send(lsuPacket)
            time.sleep(self.lsuint)

    def start(self, *args, **kwargs):
        super(LSUSender, self).start(*args, **kwargs)
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(LSUSender, self).join(*args, **kwargs)

    def send(self, *args, **override_kwargs):
        pkt = args[0]
        assert CPUMetadata in pkt, "Controller must send packets with special header"
        pkt[CPUMetadata].fromCpu = 1
        kwargs = dict(iface=self.iface, verbose=False)
        kwargs.update(override_kwargs)
        sendp(*args, **kwargs)