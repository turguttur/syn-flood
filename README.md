# syn-flood
TCP Syn Flood Attack

IP HEADER:

	0     1     2     3     4     5     6     7     8     9     10    11    12    13    14    15    16    17    18    19    20    21    22    23    24    25    26    27    28    29    30    31    32
	++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++----++
	||                      ||                      ||                                              ||                                                                                              ||
  0 ||       Version        ||  IHL(Header Length)  ||           TOS(Type of Service)               ||                                        Total Length                                          ||
	||						||						||												||				  																				||
	++----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------++
	||     	                                                                                        ||    IP Flags    ||                                                                            ||
  4	||                                          Identification                                      ||    ||    ||    ||                        Fragment Offset                                     ||
    ||                                                                                              || x  || D  || M  ||                                                                            || 
    ||                                                                                              ||    ||    ||    ||                                                                            ||
    ++----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------++
    ||                                              ||                                              ||                                                                                              || 
  8 ||		        TTL(Time to Live)               ||                   Protocol					||                                        Header Checksum                                       || 
    ||                                              ||                                              ||                                                                                              ||
    ++----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------++
    ||																																																||				
 12 ||                                                                                       SOURCE ADDRESS 																						||
    ||																																																||	
    ++----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------++
    ||																																																||	
 16 ||																					   DESTINATION ADDRESS 																						||	
    ||																																																||
    ++----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------++
    ||																																																||
 20 ||																			IP Option(variable length, optional, not common)																	||
    ||																																																||
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
