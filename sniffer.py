import os, time, psutil, threading, keyboard
from scapy.all import *
from scapy.utils import PcapWriter

class Sniffer(Thread):
    def  __init__(self, prevrun, timeout, offset, maxruns, fname):
        Thread.__init__(self)
        self.daemon = True
        self.interface = list(psutil.net_if_addrs().keys())[0]
        self.socket = conf.L2listen(type=ETH_P_ALL, iface=self.interface)
        self.stop_sniffer = False
        self.sniff = AsyncSniffer(opened_socket=self.socket, prn=self.perpacket, stop_filter=self.stopcond)

        self.maxruns = maxruns
        self.thisrun = prevrun+1
        self.name = "Class"+str(self.thisrun)
        self.child = None

        self.start_time = time.time()
        self.timeout = timeout
        self.end_time = self.start_time+self.timeout
        self.offset = offset
        
        self.fname = fname
        self.filename = self.fname+str(self.thisrun)+".pcap"
        if os.path.exists(self.filename): os.remove(self.filename)
        self.pktdump = PcapWriter(self.filename, append=True, sync=False)
        self.timer = threading.Thread(name="timer"+str(self.thisrun), target=self.timer, daemon=True)
    def run(self):
        print(self.thisrun, "Start.")
        self.timer.start()
        self.sniff.start()
        self.timer.join()
        self.join()
        print(self.thisrun, "Stopped.")
    def join(self):
        self.socket.close()
        self.sniff.stop()
        self.stop_sniffer = True
        self.pktdump.close()
        if self.child != None:
            while self.child.isAlive() != False:
                time.sleep(0.1)
    def stop(self):
        if self.child != None:
            if self.child.isAlive() != False:
                self.child.stop()
        if self.stop_sniffer == False:
            self.stop_sniffer = True
            self.end_time = 0
            self.socket.close()
    def perpacket(self, packet):
        # self.display(packet)
        self.pktdump.write(packet)
    def stopcond(self, packet):
        return self.stop_sniffer
    def display(self, packet):
        try:
            src = packet[IP].src
        except:
            src = packet.src
        try:
            dst = packet[IP].dst
        except:
            dst = packet.dst
        print(self.thisrun, ":", src, "->", dst, ":", packet.time-self.start_time)
    def timer(self):
        while True:
            time.sleep(0.1)
            t = time.time()
            if t > self.end_time:
                break
            else:
                if t > self.end_time-self.offset and self.thisrun < self.maxruns and self.child == None:
                    self.child = Sniffer(self.thisrun, self.timeout, self.offset, self.maxruns, self.fname)
                    self.child.start()
        print(self.thisrun, "Done.")

def begin(thisrun, timeout, offset, maxruns, fname):
    s = Sniffer(thisrun, timeout, offset, maxruns, fname)
    s.start()
    return s

def stop(s):
    s.stop()
    while s.isAlive():
        time.sleep(0.1)

def interrupt(s, t_end):
    while True:
        time.sleep(0.01)
        t = time.time()
        # if t > t_end:
            # print("Timeout Interrupt.")
            # stop(s)
            # break
        if keyboard.is_pressed('q'):
            print("Key Interrupt.")
            stop(s)
            break

if __name__ == "__main__":
    maxruns = 200
    timeout = 60
    offset = 5 # > 4
    fname = "capture"
    s = begin(0, timeout, offset, maxruns, fname)
    t_end = time.time()+((timeout-offset)*(maxruns-1))+timeout
    t = threading.Thread(name="interrupt", target=interrupt, args=(s, t_end), daemon=True)
    t.start()
    t.join()
    # print(threading.enumerate())
    print("End.")