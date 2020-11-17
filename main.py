from p4app import P4Mininet
from my_topo import SingleSwitchTopo, TwoSwitchTopo
from controller import MacLearningController
from peewee import PWRouter, PWInterface
import time
# Add three hosts. Port 1 (h1) is reserved for the CPU.
N = 3

topo = TwoSwitchTopo(N)
net = P4Mininet(program='l2switch.p4', topo=topo, auto_arp=False)
net.start()

# Add a mcast group for all ports (except for the CPU port)
bcast_mgid1 = 1
sw1 = net.get('s1')
sw1.addMulticastGroup(mgid=bcast_mgid1, ports=[3,4]) # add 7?

# Send MAC bcast packets to the bcast multicast group
sw1.insertTableEntry(table_name='MyIngress.fwd_l2',
        match_fields={'hdr.ethernet.dstAddr': ["ff:ff:ff:ff:ff:ff"]},
        action_name='MyIngress.set_mgid',
        action_params={'mgid': bcast_mgid1})
        
bcast_mgid2 = 2
sw2 = net.get('s2')
sw2.addMulticastGroup(mgid=bcast_mgid2, ports=[5,6]) # add 8?

# Send MAC bcast packets to the bcast multicast group
sw2.insertTableEntry(table_name='MyIngress.fwd_l2',
        match_fields={'hdr.ethernet.dstAddr': ["ff:ff:ff:ff:ff:ff"]},
        action_name='MyIngress.set_mgid',
        action_params={'mgid': bcast_mgid2})


# Start the MAC learning controller
cpu1 = MacLearningController(sw1,0)
cpu1.start() # continuously sniffing on the cpu thread

cpu2 = MacLearningController(sw2,1)
cpu2.start() # continuously sniffing on the cpu thread

h3, h4, h5, h6 = net.get('h3'), net.get('h4'), net.get('h5'), net.get('h6')
# # # Manual IP forwarding rules until I implement OSPF
# sw1.insertTableEntry(table_name='MyIngress.ipv4_lpm',
#                     match_fields={'hdr.ipv4.dstAddr': ['10.0.1.0', 24]}, # 32 is # bits
#                     action_name='MyIngress.ipv4_route',
#                     action_params={#'nextHopIP': cpu2.router.interfaces[0].ipAddr,
#                                     'port': 7})
# sw2.insertTableEntry(table_name='MyIngress.ipv4_lpm',
#                     match_fields={'hdr.ipv4.dstAddr': ['10.0.0.0', 24]}, # 32 is # bits
#                     action_name='MyIngress.ipv4_route',
#                     action_params={#'nextHopIP': cpu2.router.interfaces[0].ipAddr,
#                                     'port': 8})

print h5.cmd('arping -c1 10.0.1.6')
print h3.cmd('arping -c1 10.0.0.4')
time.sleep(20)
print h3.cmd('ping -c1 10.0.1.5')
print h3.cmd('ping -c1 10.0.1.6')
print h4.cmd('ping -c1 10.0.1.5')
print h4.cmd('ping -c1 10.0.1.6')

print h5.cmd('ping -c1 10.0.0.3')
print h5.cmd('ping -c1 10.0.0.4')
print h6.cmd('ping -c1 10.0.0.3')
print h6.cmd('ping -c1 10.0.0.4')

# These table entries were added by the CPU:
sw1.printTableEntries()
sw2.printTableEntries()
