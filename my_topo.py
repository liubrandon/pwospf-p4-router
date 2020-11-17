from mininet.topo import Topo

class SingleSwitchTopo(Topo):
    def __init__(self, n, **opts):
        Topo.__init__(self, **opts)

        switch = self.addSwitch('s1')
        # switch2 = self.addSwitch('s2')
        # self.addLink(switch, switch2, port1=6,port2=5)
        for i in xrange(1, n+1):
            host = self.addHost('h%d' % i,
                                ip = "10.0.0.%d" % i,
                                mac = '00:00:00:00:00:%02x' % i)
            self.addLink(host, switch, port2=i)

class TwoSwitchTopo(Topo):
    def __init__(self, n, **opts):
        Topo.__init__(self, **opts)

        switch1 = self.addSwitch('s1')
        switch2 = self.addSwitch('s2')
        host1 = self.addHost('h1',ip = "10.0.0.1",mac = '00:00:00:00:00:01')
        host3 = self.addHost('h3',ip = "10.0.0.3",mac = '00:00:00:00:00:03')
        host4 = self.addHost('h4',ip = "10.0.0.4",mac = '00:00:00:00:00:04')

        host2 = self.addHost('h2',ip = "10.0.1.2",mac = '00:00:00:00:00:02')
        host5 = self.addHost('h5',ip = "10.0.1.5",mac = '00:00:00:00:00:05')
        host6 = self.addHost('h6',ip = "10.0.1.6",mac = '00:00:00:00:00:06')
        self.addLink(host1, switch1, port2=1) # CPU for s1
        self.addLink(host3, switch1, port2=3) 
        self.addLink(host4, switch1, port2=4) 

        self.addLink(host2, switch2, port2=1) # CPU for s2
        self.addLink(host5, switch2, port2=5) 
        self.addLink(host6, switch2, port2=6) 

        self.addLink(switch1,switch2,port1=7,port2=8) # s1 connected to s2
        # host1 = self.addHost('h%d' % 1,
        #                     ip = "10.0.0.%d" % 1,
        #                     mac = '00:00:00:00:00:%02x' % 1)
        # self.addLink(host1, switch1, port2=1)        
        # self.addLink(host1, switch2, port2=1)        
        # for i in xrange(2, (n//2)+2):
        #     host = self.addHost('h%d' % i,
        #                         ip = "10.0.0.%d" % i,
        #                         mac = '00:00:00:00:00:%02x' % i)
        #     self.addLink(host, switch1, port2=i)

        # for i in xrange((n//2)+2, n+1):
        #     host = self.addHost('h%d' % i,
        #                         ip = "10.0.0.%d" % i,
        #                         mac = '00:00:00:00:00:%02x' % i)
        #     self.addLink(host, switch2, port2=i)