from scapy.all import *
from datetime import datetime

def detect_icmp_traffic(interface, duration=60):
    """
    Detect and log ICMP traffic on a specified network interface.
    
    :param interface: Network interface to monitor
    :param duration: Time to capture packets (in seconds)
    """
    print(f"[*] Starting ICMP traffic detection on {interface} for {duration} seconds")
    
    def packet_callback(packet):
        """
        Callback function to process captured packets
        """
        if ICMP in packet:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            icmp_type = packet[ICMP].type
            
            print(f"[ICMP] {timestamp} - "
                  f"Source: {src_ip} | "
                  f"Destination: {dst_ip} | "
                  f"Type: {icmp_type}")
    
    # Sniff packets on the specified interface
    sniff(
        iface=interface,  # Network interface to monitor
        prn=packet_callback,  # Callback function for each packet
        timeout=duration,  # Duration of packet capture
        filter="icmp"  # Filter for ICMP packets only
    )

def main():
    interface = "eth0"  # Common interface name, adjust as needed
    # interface = "vmi.edu"  # Common interface name, adjust as needed
    detect_icmp_traffic(interface)

if __name__ == "__main__":
    main()