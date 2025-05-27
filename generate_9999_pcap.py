from scapy.all import IP, TCP, Ether, wrpcap

# Create a TCP SYN packet to port 9999
pkt = Ether() / IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=12345, dport=9999, flags="S")

# Save to a PCAP file
wrpcap("test_9999_enrich.pcap", [pkt])

print("✅ test_9999_enrich.pcap has been created!")
