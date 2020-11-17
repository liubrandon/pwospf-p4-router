from collections import defaultdict, deque
MAX_INTERFACES = 10
class PWRouter():
    def __init__(self, sw, routerNum, areaID, lsuint = 30):
        self.sw = sw
        self.routerID = "10.0."+str(routerNum)+".0"
        self.areaID = areaID
        self.lsuint = lsuint # default value of 30 seconds
        self.interfaces = [None,None]
        self.topology = TopoData(self.sw, self.routerID, self.interfaces)
        for i in range(2,MAX_INTERFACES+1): # assume 10 interfaces
            ipAddr = self.routerID[:-1] + str(i)
            netMask = "255.255.255.0"
            helloint = 3
            self.interfaces.append(PWInterface(ipAddr, netMask, helloint))
    
class PWInterface():
    def __init__(self, ipAddr, netMask, helloint):
        self.ipAddr = ipAddr
        self.netMask = netMask
        self.helloint = helloint
        self.neighbors = {}

class TopoData():
    def __init__(self, sw, routerID, interfaces):
        self.sw = sw
        self.routerID = routerID
        self.interfaces = interfaces
        self.graph = defaultdict(lambda: []) # key = routerIDs, values = [neighborRouterID, ...]
        self.bestPortToRouter = defaultdict()  # keys = routerIDs, values = port
        self.subnetsAtRouter = defaultdict(lambda: []) # keys = routerIDs, values = [(subnet, mask), ...]
        self.installedSubnetRules = set()

    def updateBestPorts(self):        
        # Firstly, the best ports for any neighbors are the ports they are connected to
        # For each non-cpu interface (port)
        q = deque()
        visited = set()
        visited.add(self.routerID)
        for i in range(2, len(self.interfaces)):
            for routerID, _ in self.interfaces[i].neighbors.values():
                if routerID not in visited: # don't overcount routers with multiple links connecting to it
                    self.bestPortToRouter[routerID] = i
                    visited.add(routerID)
                    q.append(routerID)
        # Next, use BFS to determine the best port to reach every other router
        # Simply, the best port of a given router will also be the best port
        # of its unvisited neighbors. BFS works in place of dijkstra's algorithm
        # because each edge is unweighted.
        while q:
            currRouterID = q.popleft()
            currBestPort = self.bestPortToRouter[currRouterID]
            for neighborRouterID in self.graph[currRouterID]:
                if neighborRouterID not in visited:
                    q.append(neighborRouterID)
                    visited.add(neighborRouterID)
                    self.bestPortToRouter[neighborRouterID] = currBestPort
    
    # After computing best ports, install the corresponding rules in the data plane
    def installForwardingRules(self):
        for routerID, port in self.bestPortToRouter.items():
            for subnet in self.subnetsAtRouter[routerID]: # mask is hardcoded to 24 (TODO: use any mask)
                # we know every subnet that every router can access
                # we know the best port to get to every router
                # install the rules in this switch such that you can access 
                # every subnet by going to that best port
                if subnet not in self.installedSubnetRules: # install a rule for a subnet only once
                    self.sw.insertTableEntry(table_name='MyIngress.ipv4_lpm',
                                            match_fields={'hdr.ipv4.dstAddr': [subnet, 24]}, # 32 is # bits
                                            action_name='MyIngress.ipv4_route',
                                            action_params={'port': port})
                    self.installedSubnetRules.add(subnet)




        
