from scapy.all import *
from threading import Thread

# Creating and sending a packet:
spam_packet = Ether(dst="00:15:5d:76:90:c0")/IP(dst="172.19.188.134",src="1.2.3.4", ttl=(1,100))/TCP(dport=42069, flags="S")/Raw(RandBin(size=150)) # Could also use RandBin().

weird_packet1 = Ether(dst="00:15:5d:76:90:c0")/IP(dst="172.19.188.134",src="172.19.188.255", ttl=(1,17))/TCP(dport=21, flags="S")/Raw("0xFFAF0190DF9G") # Could also use RandBin().
wierd_packet2 = Ether(dst="00:15:5d:76:90:c0")/IP(dst="172.19.188.134",src="172.19.188.255", ttl=(1,4))/TCP(dport=22, flags="S")/Raw("0x000001229000") # Could also use RandBin().
wierd_packet3 = Ether(dst="00:15:5d:76:90:c0")/IP(dst="172.19.188.134",src="172.19.188.255", ttl=(1,50))/TCP(dport=23, flags="S")/Raw("0x00070G0339D1") # Could also use RandBin().


# Send a packet, or list of packets without custom ether layer:

def loop():
    print("STARTED~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    for i in range(10):
        sendp(spam_packet)
        if i % 3 == 1:
            sendp(weird_packet1)
        elif i % 3 == 2:
            sendp(wierd_packet2)
        elif i % 3 == 3:
            sendp(wierd_packet3)
            
if __name__ == "__main__":
    t1 = Thread(name="loop1", target=loop)
    t2 = Thread(name="loop2", target=loop)
    t3 = Thread(name="loop3", target=loop)
    t4 = Thread(name="loop4", target=loop)
    t5 = Thread(name="loop5", target=loop)

    t1.start()
    t2.start()
    t3.start()
    t4.start()
    t5.start()

    t1.join()
    t2.join()
    t3.join()
    t4.join()
    t5.join()
