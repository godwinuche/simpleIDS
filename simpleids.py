import socket

# create a raw socket and bind it to the public interface
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
s.bind(("eth0", 0))

# include the IP headers in the captured packets
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# receive all packages
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# read in a single packet
packet = s.recvfrom(65565)

# disable promiscuous mode
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

# extract the raw data from the packet
data = packet[0]

# get the IP header (the first 20 bytes) and unpack them
ip_header = data[:20]
ip_header = struct.unpack("!BBHHHBBH4s4s", ip_header)

# get the IP source and destination
ip_src = socket.inet_ntoa(ip_header[8])
ip_dst = socket.inet_ntoa(ip_header[9])

# get the TCP header (the next 20 bytes) and unpack them
tcp_header = data[20:40]
tcp_header = struct.unpack("!HHLLBBHHH", tcp_header)

# get the TCP source and destination ports
tcp_src = tcp_header[0]
tcp_dst = tcp_header[1]

# check for a ping sweep or port scan
if (tcp_src == 80 and tcp_dst == 80) or (tcp_src == 80 and tcp_dst == 80):
  print("ALERT: Ping sweep or port scan detected!")
