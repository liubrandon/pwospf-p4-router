from threading import Thread, Event
import time
from myPackets import PWOSPF, Hello
from scapy.all import Packet, Ether, IP, ARP
from scapy.all import sendp
from peewee import PWRouter, PWInterface
from cpu_metadata import CPUMetadata

ALLSPFRouters = "224.0.0.5" #0xe0000005
IP_PROT_PWOSPF = 89
PWOSPF_TYPE_HELLO = 1
NETMASK = "255.255.255.0" #0xffffff00
class HelloProtocol(Thread):
    def __init__(self, sw, router, iface, start_wait=0.3):
        super(HelloProtocol, self).__init__() # Initializes Thread object
        self.stop_event = Event() # Thread API thing, do this event when the thread is stopped?
        self.start_wait = start_wait # time to wait for the controller to be listenning
        self.router = router
        self.iface = iface
        self.sw = sw
        self.senderThreads = [None, None]
        # Create a HelloSender thread to send Hello packets our of each interface (port)
        # Skip 1 as it is the CPU
        for i in range(2,len(router.interfaces)):
            # set the egress_port to the corresponding interface given the corresponding ipv4 source
            self.sw.insertTableEntry(table_name='MyIngress.one_hop',
                                    match_fields={'hdr.ipv4.srcAddr': [self.router.interfaces[i].ipAddr]},
                                    action_name='MyIngress.set_egr',
                                    action_params={'port': i})
            if i == 7:
                self.senderThreads.append(HelloSender(router, i, self.router.interfaces[i].helloint, iface, False))
            else:
                self.senderThreads.append(HelloSender(router, i, self.router.interfaces[i].helloint, iface))
        for i in range(2,len(router.interfaces)):
            self.senderThreads[i].start()

    def run(self):
        pass

    def start(self, *args, **kwargs):
        super(HelloProtocol, self).start(*args, **kwargs)
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(HelloProtocol, self).join(*args, **kwargs)
    
class HelloSender(Thread):
    def __init__(self, router, egressPort, helloint, iface, terminate = False, start_wait=0.3):
        super(HelloSender, self).__init__() # Initializes Thread object
        self.stop_event = Event() # Thread API thing, do this event when the thread is stopped?
        self.start_wait = start_wait # time to wait for the controller to be listenning
        self.egressPort = egressPort
        self.router = router
        self.helloint = helloint
        self.iface = iface
        self.terminate = terminate
        etherLayer  = Ether()
        cpuLayer    = CPUMetadata(fromCpu=1,origEtherType=0x800)
        ipLayer     = IP(src=self.router.interfaces[self.egressPort].ipAddr,dst=ALLSPFRouters,proto=IP_PROT_PWOSPF)
        pwospfLayer = PWOSPF(type=PWOSPF_TYPE_HELLO,length=32,routerID=self.router.routerID,areaID=0,checksum=0)
        helloLayer  = Hello(netMask=NETMASK,helloint=self.helloint)
        self.helloPacket = etherLayer/cpuLayer/ipLayer/pwospfLayer/helloLayer
        
    def run(self):
        count = 0
        while True:
            self.send(self.helloPacket)
            if count == 10 and self.terminate:
                print("Hello sender thread killed!")
                break
            time.sleep(self.helloint)
            count+=1

    def start(self, *args, **kwargs):
        super(HelloSender, self).start(*args, **kwargs)
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(HelloSender, self).join(*args, **kwargs)

    def send(self, *args, **override_kwargs):
        pkt = args[0]
        assert CPUMetadata in pkt, "Controller must send packets with special header"
        pkt[CPUMetadata].fromCpu = 1
        kwargs = dict(iface=self.iface, verbose=False)
        kwargs.update(override_kwargs)
        sendp(*args, **kwargs)