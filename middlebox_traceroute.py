import sys
from scapy.all import *
import socket

src = sys.argv[1]
dst = sys.argv[2]
sport = random.randint(1024,65535)
dport = int(sys.argv[3])

print "Binding socket..."
s = socket.socket(
    socket.AF_INET, socket.SOCK_STREAM)
s.bind((src, sport))

print "Initiating 3-way handshake with the actual server..."

# SYN
ip=IP(src=src,dst=dst,ttl=50)
SYN=TCP(sport=sport,dport=dport,flags='S',seq=1010)
SYNACK=sr1(ip/SYN, verbose=0, timeout=1)

if SYNACK is None:
    print "Error finishing handshake!"
    exit (1)

# ACK
sq = SYNACK.ack
ak = SYNACK.seq + 1
ACK=TCP(sport=sport, dport=dport, flags='A', seq=int(sq), ack =int(ak))
send(ip/ACK, verbose=0)

print "Handshake done! SYNACK soucre: %s SYNACK TTL: %d" %(SYNACK[IP].src, SYNACK[IP].ttl)
SYNACK.show()

# HTTP GET
get = "GET / HTTP/1.1\r\nHost: %s\r\n\r\n" %(dst)

print "Trying this censored payload:"
print get

GET=TCP(sport=sport, dport=dport, flags='PA', ack=ak, seq=sq)
for ttl in range(1,20):
    ip.ttl = ttl
    print "* Limiting data TTL to %d" % (ip.ttl)
    packets, unanswered = sr(ip/GET/get, verbose = 0, timeout=0.5)
    for pair in packets:
	req, packet = pair
	if Raw in packet:
	    # this part can be replaced with a your detection method of choice
	    if 'src="http://10.10.34.34' in packet[Raw].load:
	        #packet[Raw]
		print "*** Found censored payload at hop #%d: %s (response TTL: %d)" % (ttl, packet[IP].src, packet[IP].ttl)
		print packet[Raw]
		sys.exit(0)
	    print "Response:" 
	    print packet[Raw].load
	    print "IP: %s TTL: %d" % (packet[IP].src, packet[IP].ttl)
