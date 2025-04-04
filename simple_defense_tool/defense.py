from scapy.all import *
from threading import Thread
import sys

debug = False
interface = ""

traffic_ips = [
    ["192.168.1.1", 1]
]

blocked_ips = {
        "192.168.1.100",
        ""
    }

'''
Prints the current blacklist of IPs to the console
'''
def print_blacklist():
    print("\nBLACKLIST")
    for ip_addr in blocked_ips:
        print(ip_addr)
    print("\n")

'''
Prints the current blacklist of IPs and all other traffic to the console
'''
def print_all_traffic():
    print("\nAll Traffic")
    print("\nIPv4 Address\tInstances")
    for entry in traffic_ips:
        print(f"{entry[0]}\t{entry[1]}")

'''
Increments an entry for an existing IP, or creates a new entry for new traffic

:param src_ip: Source address passed from packet_filter()
:param dst_ip: Destination address passed from packet_filter()
'''
def log_traffic(src_ip, dst_ip):
    src_found, dst_found = False
    for entry[0] in traffic_ips:
        if src_ip in traffic_ips[0]:
            entry[1] += 1
            src_found = True
        if dst_ip in traffic_ips[0]:
            entry[1] += 1
            dst_found = True
        if src_found & dst_found:
            return True
    
    if(not src_found):
        traffic_ips.append([src_ip, 0])
        
    if(not dst_found):
        traffic_ips.append([dst_ip, 0])

def add_to_blacklist(src_ip, dst_ip):
    for entry in blocked_ips:
        if entry == src_ip:
            blocked_ips.append(src_ip)
        if entry == dst_ip:
            blocked_ips.append(dst_ip)

            '''
            <<<<Add IPtables rules here>>>>
            '''

'''
Detects packets that are not allowed. 

:param packet: the packet passed from sniff()
:returns: True if global debug, otherwise, false
'''
def packet_filter(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if src_ip in blocked_ips or dst_ip in blocked_ips:
            print(f"[!] Detected unauthorized traffic: {src_ip} -> {dst_ip}")
            return None

        if(TCP in packet):
            match packet[TCP].dport:
                case 20, 21, 152, 989, 990:
                    print(f"[!] Detected TCP FTP packet to {dst_ip} from {src_ip}")
                case 22, 830:
                    print(f"[!] Detected TCP SSH packet to {dst_ip} from {src_ip}")
                case 23, 992:
                    print(f"[!] Detected TCP Telnet packet to {dst_ip} from {src_ip}")
                case 3389:
                    print(f"[!] Detected TCP Windows RDP packet to {dst_ip} from {src_ip}")
                case packet if packet[TCP].dport in range(1000,65000):
                    print(f"[!] Detected TCP Unknown taffic {dst_ip} from {src_ip}")

        if ICMP in packet:
            print(f"[!] Detected ICMP packet from {src_ip}")
            return None

        # Logs both source and destination addresses
        log_traffic(src_ip, dst_ip)

        if(debug):
            return packet
    else:
        print("[*] Other Network Traffic")
    return None

def main():
    print("[*] Started Monitoring...")
    try:
        # iface is network interface, prn todo after getting a packet, do not store packets
        sniff( iface=interface, prn=packet_filter, store=0 )
        
    except PermissionError:
        print("[*] Access Denied. Are you root?")

if __name__ == "__main__":

    try:
        if(sys.argv[1] == "-help"):
            print("Usage:\n\tsudo path/to/python3 path/to/defense.py [interface|str] [\"-drop\"|optional] [\"--debug\"|optional] \n\nOr consider the arguments:\n\t-help (prints this message)\n\t-print\n\t-printall")
            exit()
        if(sys.argv[1] == "-print"):
            print_blacklist()
            exit()
        if(sys.argv[1] == "-printall"):
            print_blacklist()
            print_all_traffic()
            exit()
        interface = sys.argv[1]

        for iter in sys.argv[2:]:            
            if(iter == "-drop"):
                print("[*] \"Drop\" is not avaliable. Packet manipulation is not enabled in module. Continuing.")
            if(iter == "--debug"):
                debug = True

    except KeyboardInterrupt:
        print("\n[*] Stopping packet interceptor...")

    except IndexError:
        print("[*] Missing arguments.  Try --> \"-help\"")
        exit()

    except TypeError:
        print("[*] Illegal argument type.  Try --> \"-help\"")
        exit()
    
    main()