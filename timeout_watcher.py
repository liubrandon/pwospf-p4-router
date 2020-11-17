from threading import Thread, Event
import time
from myPackets import PWOSPF, Hello
from peewee import PWRouter, PWInterface

class TimeoutWatcher(Thread):
    def __init__(self, router, start_wait=0.3):
        super(TimeoutWatcher, self).__init__() # Initializes Thread object
        self.stop_event = Event() # Thread API thing, do this event when the thread is stopped?
        self.start_wait = start_wait # time to wait for the controller to be listenning
        self.router = router
        self.watcherThreads = [None, None]
        # Create a PortTimeoutWatcher thread to watch each interface (port)
        # Skip 1 as it is the CPU
        for portNum in range(2,len(router.interfaces)):
            self.watcherThreads.append(PortTimeoutWatcher(router, portNum))
        for portNum in range(2,len(router.interfaces)):
            self.watcherThreads[portNum].start()

    def run(self):
        pass

    def start(self, *args, **kwargs):
        super(TimeoutWatcher, self).start(*args, **kwargs)
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(TimeoutWatcher, self).join(*args, **kwargs)
    
class PortTimeoutWatcher(Thread):
    def __init__(self, router, portNum, start_wait=0.3):
        super(PortTimeoutWatcher, self).__init__() # Initializes Thread object
        self.stop_event = Event() # Thread API thing, do this event when the thread is stopped?
        self.start_wait = start_wait # time to wait for the controller to be listenning
        self.portNum = portNum
        self.router = router
    
    def getTimeoutThreshholds(self):
        timeoutThresholds = []
        NEIGHBOR_TIMEOUT = 3*self.router.interfaces[self.portNum].helloint
        for neighborIP, routerIDandUpdateTime in self.router.interfaces[self.portNum].neighbors.items():
            updateTime = routerIDandUpdateTime[1]
            timeoutThresholds.append((neighborIP, updateTime+NEIGHBOR_TIMEOUT))
        return timeoutThresholds

    def run(self): # sniff has a while True loop
        while True:
            timeoutThresholds = self.getTimeoutThreshholds()
            currTime = time.time()
            for neighborIP, thresh in timeoutThresholds:
                # print("currTime-thresh:", currTime-thresh)
                if currTime >= thresh:
                    print("%s connected to router %s on port %d has timed-out. Should remove forwarding rules and recompute paths/ports." % (neighborIP, self.router.routerID, self.portNum))
                    return
                

    def start(self, *args, **kwargs):
        super(PortTimeoutWatcher, self).start(*args, **kwargs)
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(PortTimeoutWatcher, self).join(*args, **kwargs)