#include "tcp.h"

/*******************************************************************************
 *	File: tcp.c
 *	Desc: creates tcp packets and sends them.
 *
 ******************************************************************************/

int main(int argc, char **argv){
	int x;
	int fags[] = {1, 1, 1, 1, 1, 1, 1, 1};
	// test packet builder
	x = build_tcp_packet(argv[1], fags);
	return 0;
}

/*******************************************************************************
 *	unsigned short int chksum(unsigned short int *addr, int length):
 *	computes a checksum for the IP+TCP header it is called on.
 ******************************************************************************/
unsigned short int compute_chksum(unsigned short int *addr, int length){
	int nleft = length;
	int sum = 0;
	unsigned short int *w = addr;
	unsigned short int answer = 0;
	
	while(nleft > 1){
		sum += *w++;
		nleft -= sizeof(unsigned short int);
	}
	
	if(nleft == 1){
		*(unsigned char *) (&answer) = *(unsigned char *) w;
	}
	
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}

/*******************************************************************************
 *	unsigned short int tcp_chksum(struct ip ipheader, struct tcphdr tcpheader):
 *	
 *	We use a buffer of size IP_MAXPACKET (65,535 bytes, defined in netinet/ip.h).
 *  First we build the pseudo-header, which will be included when we do the
 *	checksum calc.  It contains important info taken from fields in both the TCP
 *	and IP datagram.  The pseudo-header (12 bytes) is followed by the actual TCP
 *	header up to the `options' fields.  The Options and the data are both  
 *  variable length fields. 
 *  The pseudo-header layout:
 *  |0_________________________________15_________________________________31|
 *  |                           Source IP Address                           |
 *  |                       Destination IP Address                          |
 *  |   reserved    |   IP Protocol    |         TCP Segment Length         |
 *  ************************************************************************/
 /*  Here's the TCP segment layout:
 *  |0_________________________________15_________________________________31|
 *  |          Source Port              |           Destination Port        |
 *  |                           Sequence Number                             |
 *  |                         Acknowledgement Number                        |
 *  |Data Offset|reserved|Control bits  |              Window               |
 *  |            Checksum               |           Urgent Pointer          |
 *  |  Option Kind 1 | Option Length 1	|           Option Data 1           |
 *  |            .....                                   .....              |
 *  |            .....                  |  Option Kind n | Option Length n	|
 *  |            Option Data n                           |	    Padding     |
 *  |            Data                   |                .....              |
 *  |            .                      |                .                  |
 *  |            .                      |                .                  |
 *  |            .                      |                .                  |
 ***************************************************************************/
unsigned short int tcp_chksum(struct ip ipheader, struct tcphdr tcpheader){

	unsigned short int sz;
	char buf[IP_MAXPACKET], offset_bytes;
	char *buf_p;
	int chksumsz = 0;
	buf_p = &buf[0];

	/* The general algorithm here is to use memcpy() to build each field of  *
	 * the packet headers.  Then we update our convenience pointer and 		 *
	 * checksum counter with the size of the field so we know the header     *
	 * lengths when we go to compute the checksum.							 */

	/**** START PSEUDO HEADER ****/
	/* Source IP is first thing we need. 4 bytes. */
	memcpy(buf_p, &ipheader.ip_src.s_addr, sizeof(ipheader.ip_src.s_addr));
	buf_p += sizeof(ipheader.ip_src.s_addr);
	chksumsz += sizeof(ipheader.ip_src.s_addr);

	/* Destination IP.  Also 4 bytes. */
	memcpy(buf_p, &ipheader.ip_dst.s_addr, sizeof(ipheader.ip_dst.s_addr));
	buf_p += sizeof(ipheader.ip_dst.s_addr);
	chksumsz += sizeof(ipheader.ip_dst.s_addr);

	/* `reserved' field is set to all zeros. 1 byte. */
	*buf_p = 0; buf_p++;
	chksumsz += 1;

	/* `Protocol' Need to reference IP header for this. 1 byte. */
	memcpy(buf_p, &ipheader.ip_p, sizeof(ipheader.ip_p));
	buf_p += sizeof(ipheader.ip_p);
	chksumsz += sizeof(ipheader.ip_p);

	/* TCP Segment Length.  Length of both header and data in tcp segment. */
	sz = htons(sizeof(tcpheader));
	memcpy (buf_p, &sz, sizeof(sz));
	buf_p += sizeof(sz);
	chksumsz += sizeof(sz);
	/**** END PSEUDO HEADER ****/
	
	/**** START TCP HEADER ****/
	/* Source Port, 2 bytes. */
	memcpy(buf_p, &tcpheader.th_sport, sizeof(tcpheader.th_sport));
	buf_p += sizeof(tcpheader.th_sport);
	chksumsz += sizeof(tcpheader.th_sport);

	/* Destination port, also 2 bytes */
	memcpy(buf_p, &tcpheader.th_dport, sizeof(tcpheader.th_dport));
	buf_p += sizeof(tcpheader.th_dport);
	  chksumsz += sizeof(tcpheader.th_dport);

	/* Sequence number of first byte of data in this segment.  (32 bits) */
	memcpy (buf_p, &tcpheader.th_seq, sizeof(tcpheader.th_seq));
	buf_p += sizeof (tcpheader.th_seq);
	chksumsz += sizeof (tcpheader.th_seq);

	/* Acknowledgment number.  If ACK bit is set, serves as acknowledgment *
	 * (this segment could have other duties, though), and this field 	   *
	 * contains the sequence number the source is next expecting the 	   *
	 * destination to send.   (32 bits) 								   */
	memcpy(buf_p, &tcpheader.th_ack, sizeof(tcpheader.th_ack));
	buf_p += sizeof(tcpheader.th_ack);
	chksumsz += sizeof(tcpheader.th_ack);

	/* `data offset' field specifies number of 32-bit words of data in our *
	 * TCP header (must be multiple of 4). 1 nibble or 1/2 byte.		   *
	 * `reserved' bytes, 6 bits.  */
	offset_bytes = (tcpheader.th_off << 4) + tcpheader.th_x2;
	memcpy(buf_p, &offset_bytes, sizeof(offset_bytes));
	buf_p += sizeof(offset_bytes);
	chksumsz += sizeof(offset_bytes);

	/* Control bits used to indicate communication of control messages.    *
	 * [URG: indicates priority feature has been invoked on this segment,  *
	 *  ACK: when set, this segment is an ACK packet.					   *
	 *  PSH: sender of this segment wants data pushed asap to application. *
	 *  RST: problem encoutered, reset connection.						   *
	 *  SYN: this segment is a request to synch sequence numbers /         *
	 *       establish a connection.									   *
	 *  FIN: sender of this segment is requesting to end the connection.]  *
	 *  6 bits total.															   */
	memcpy (buf_p, &tcpheader.th_flags, sizeof(tcpheader.th_flags));
	buf_p += sizeof (tcpheader.th_flags);
	chksumsz += sizeof (tcpheader.th_flags);

	/* Number of octets of data sender of this segment is willing to accept *
	 * from the receiver at a time.  normally corresponds to the current    *
	 * size of the buffer allocated to accept data for this connection.     */
	memcpy(buf_p, &tcpheader.th_win, sizeof(tcpheader.th_win));
	buf_p += sizeof(tcpheader.th_win);
	chksumsz += sizeof(tcpheader.th_win);

	/* Checksum field, TCP says this must be zeroed out while computing it.  *
	 * 2 bytes. 														     */
	*buf_p = 0; buf_p++;
	*buf_p = 0; buf_p++;
	chksumsz += 2;

	/* Urgent pointer field used in conjunction with URG control bit for 	 *
	 * priority data transfer.  This field contains the sequence number of   *
	 * the last byte of urgent data.   										 */
	memcpy(buf_p, &tcpheader.th_urp, sizeof(tcpheader.th_urp));
	buf_p += sizeof(tcpheader.th_urp);
	chksumsz += sizeof(tcpheader.th_urp);
	
	/**** END TCP HEADER ****/
	
	return compute_chksum((unsigned short int *)buf, chksumsz);
}

/*******************************************************************************
 *	int build_tcp_packet(char *iface, int *flags_ptr):
 *	
 *	Construct a TCP packet with IP datagram header too.  
 *   -------------------------------------------------------------------------
 *  |0_________________________________15_________________________________31|
 *  | Version | IHL* | Type of Service*	|		Total Length (TL)			|
 *  |           Identification          |   Flags*  |     Fragment Offset   |
 *  |  Time To Live   | Protocol        |       Header Checksum             |
 *  |                           Source Addresss                             |
 *  |                           Destination Addresss                        |
 *  |           Options                                     |   Padding     |
 *  |           Data                                                        |
 *  -------------------------------------------------------------------------
 * IHL = Internet Header Lenght
 * TOS = Precedence:0-2 Delay:3 Throughput:4 Reliability:5 Reserved:6,7
 * Flags = Reserved:0, Don't Fragment (DF):1, More Fragments (MF):2
 * 
 ******************************************************************************/
int build_tcp_packet(char *iface, int *flags_ptr){
	int i, status, sock;
	const int on = 1;
	char *interface, *target, *source_ipaddr, *dest_ipaddr;
	struct ip ipheader;
	struct tcphdr tcpheader;
	unsigned char *ip_flags, *tcp_flags, *packet;
	struct addrinfo hints, *res;
	struct sockaddr_in 	*ipv4, sin;
	struct ifreq ifr;
	void *tmp;

	/* First, allocate some space on the heap for our local variables.  */
	/*  the actual packet. IP_MAXPACKET = 65,535 */
	tmp = (unsigned char *) malloc (IP_MAXPACKET * sizeof (unsigned char));
	if (tmp != NULL) {
		packet = tmp;
	} else {
		fprintf (stderr, "ERROR: Cannot allocate memory for array 'packet'.\n");
		exit (EXIT_FAILURE);
	}
	memset (packet, 0, IP_MAXPACKET);

	/* string for local network interface name (eth0, wlan0, etc.)  */
	tmp = (char *) malloc (40 * sizeof (char));
	if (tmp != NULL) {
		interface = tmp;
	} else {
	fprintf (stderr, "ERROR: Cannot allocate memory for array 'interface'.\n");
	exit (EXIT_FAILURE);
	}
	memset (interface, 0, 40);

	/* the actual packet. IP_MAXPACKET 65,535 */
	tmp = (char *) malloc (40 * sizeof (char));
	if (tmp != NULL) {
		target = tmp;
	} else {
		fprintf (stderr, "ERROR: Cannot allocate memory for array 'target'.\n");
		exit (EXIT_FAILURE);
	}
	memset (target, 0, 40);

	tmp = (char *) malloc (16 * sizeof (char));
	if (tmp != NULL) {
		source_ipaddr = tmp;
	} else {
		fprintf (stderr, "ERROR: Cannot allocate memory for array 'source_ipaddr'.\n");
		exit (EXIT_FAILURE);
	}
	memset (source_ipaddr, 0, 16);

	tmp = (char *) malloc (16 * sizeof (char));
	if (tmp != NULL) {
		dest_ipaddr = tmp;
	} else {
		fprintf (stderr, "ERROR: Cannot allocate memory for array 'dest_ipaddr'.\n");
		exit (EXIT_FAILURE);
	}
	memset (dest_ipaddr, 0, 16);

	tmp = (unsigned char *) malloc (4 * sizeof (char));
	if (tmp != NULL) {
		ip_flags = tmp;
	} else {
		fprintf (stderr, "ERROR: Cannot allocate memory for array 'ip_flags'.\n");
		exit (EXIT_FAILURE);
	}
	memset (ip_flags, 0, 4);

	tmp = (unsigned char *) malloc (16 * sizeof (char));
	if (tmp != NULL) {
		tcp_flags = tmp;
	} else {
		fprintf (stderr, "ERROR: Cannot allocate memory for array 'tcp_flags'.\n");
		exit (EXIT_FAILURE);
	}
	memset (tcp_flags, 0, 4);

	strcpy (interface, iface);

	// Submit request for a socket descriptor to lookup interface.
	if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror ("socket() failed to get socket descriptor for using ioctl() ");
		exit (EXIT_FAILURE);
	}

	/* Use ioctl() to lookup interface. */
	memset (&ifr, 0, sizeof (ifr));
	snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
	if (ioctl (sock, SIOCGIFINDEX, &ifr) < 0) {
		perror ("ioctl() failed to find interface ");
		return (EXIT_FAILURE);
	}
	close (sock);
	printf ("Index for interface %s is %i\n", interface, ifr.ifr_ifindex);

	/* users IP needs to go here */
	strcpy (source_ipaddr, "192.168.1.111");

	/* Destination URL or IPv4 address */
	strcpy (target, "133.7.133.7");

	/* Fill out hints for getaddrinfo(). */
	memset (&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = hints.ai_flags | AI_CANONNAME;

	// Resolve target using getaddrinfo().
	if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
		fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
		exit (EXIT_FAILURE);
	}
	ipv4 = (struct sockaddr_in *) res->ai_addr;
	tmp = &(ipv4->sin_addr);
	inet_ntop (AF_INET, tmp, dest_ipaddr, 16);
	freeaddrinfo (res);

	/*** START IPv4 HEADER ***/
	/* Internet Header Length: the number of 32-bit words in the header.     *
	 * Since an IPv4 header may contain a variable number of options, this   *
	 * field specifies the size of the header (this also coincides with the  *
	 * offset to the data). The minimum value for this field is 5 (RFC 791 ),* 
	 * which is a length of 5×32 = 160 bits = 20 bytes. Being a 4-bit value, *
	 * the maximum length is 15 words (15×32 bits) or 480 bits = 60 bytes.   */
	ipheader.ip_hl = IP4_HEADER_LEN / sizeof (unsigned long int);
	/* version: IPv4 (1 nibble or 4 bits) */
	ipheader.ip_v = 4;
	/* Type of Service (TOS): carries info for quality of service features 	  *
	 * like priority datagrams. 1 byte.										  */
	ipheader.ip_tos = 0;
	/* Total length of datagram (16 bits): IP header + TCP header */
	ipheader.ip_len = htons (IP4_HEADER_LEN + TCP_HEADER_LEN);
	/* ID sequence number (16 bits): unused, since we're sending a single     *
	 * datagram. */
	ipheader.ip_id = htons (0);

	/* Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram */
	/* Zero (1 bit) */
	ip_flags[0] = 0;
	/* Do not fragment flag (1 bit) */
	ip_flags[1] = 0;
	/* More fragments following flag (1 bit) */
	ip_flags[2] = 0;

	/* Fragmentation offset (13 bits) specifies the offset of a particular    *
	 * fragment relative to the beginning of the original unfragmented IP     *
	 * datagram. The first fragment has an offset of zero.					  */
	ip_flags[3] = 0;
	ipheader.ip_off = htons ((ip_flags[0] << 15) + (ip_flags[1] << 14) \
		+ (ip_flags[2] << 13) +  ip_flags[3]);
	/* Time-to-Live (8 bits): default to maximum value */
	ipheader.ip_ttl = 255;
	/* Transport layer protocol (8 bits): 6 for TCP */
	ipheader.ip_p = IPPROTO_TCP;
	/* Source IPv4 address (32 bits) */
	inet_pton (AF_INET, source_ipaddr, &(ipheader.ip_src));
	/* Destination IPv4 address (32 bits) */
	inet_pton (AF_INET, dest_ipaddr, &ipheader.ip_dst);
	/* IPv4 header checksum (16 bits): set to 0 when calculating checksum */
	ipheader.ip_sum = 0;
	ipheader.ip_sum = compute_chksum ((unsigned short int *) &ipheader, IP4_HEADER_LEN);
	
	/* TCP HEADER */
	/* Source port number (16 bits) */
	tcpheader.th_sport = htons (-1);
	/* Destination port number (16 bits) */
	tcpheader.th_dport = htons (80);
	/* Sequence number (32 bits): 
	 * If the SYN flag is set (1), then this is the initial sequence number.  *
	 * The sequence number of the actual first data byte and the acknowledged *
	 * number in the corresponding ACK are then this sequence number plus 1.  *
	 * If the SYN flag is clear (0), then this is the accumulated sequence    *
	 * number of the first data byte of this packet for the current session.  */
	tcpheader.th_seq = htonl (0);
	/* Acknowledgement number (32 bits): 0 in first packet of SYN/ACK 		  *
	 * process. If the ACK flag is set then the value of this field is the    *
	 * next sequence number that the receiver is expecting. This acknowledges *
	 * receipt of all prior bytes (if any). The first ACK sent by each end 	  *
	 * acknowledges the other end's initial sequence number itself, but no 	  *
	 * data.  */
	tcpheader.th_ack = htonl (0);
	// Reserved (4 bits): Placeholders for TCP development.  Must be zero.
	tcpheader.th_x2 = 0;
	/* Data offset (4 bits): specifies the size of the TCP header in 32-bit   *
	 * words. The minimum size header is 5 words and the maximum is 15 words  *
	 * thus giving the minimum size of 20 bytes and maximum of 60 bytes, 	  *
	 * allowing for up to 40 bytes of options in the header.  */
	tcpheader.th_off = TCP_HEADER_LEN / 4;

	/* Flag name: description */
	/* FIN: No more data from sender. */
	tcp_flags[0] = flags_ptr[0];
	/* SYN: Sync sequence numbers.  Only 1st packet sent from each end  *
	 * should have this flag set. 											 */ 
	tcp_flags[1] = flags_ptr[1];
	/* RST: Reset the connection. */
	tcp_flags[2] = flags_ptr[2];
	/* PSH: Push function. Asks to push the buffered data to the receiving 	 *
	 * device. 																 */
	tcp_flags[3] = flags_ptr[3];
	/* ACK: indicates acknowledgment field is significant.  All regular 	 *
	 * packets after the initial SYN packet sent by client should have this  *
	 * flag set. 															 */
	tcp_flags[4] = flags_ptr[4];
	// URG: Indicates the Urgent pointer field is significant.  */
	tcp_flags[5] = flags_ptr[5];
	/* ECE: (ECN-Echo) if (SYN), sender is ECN capable.  Else, congestion	 * 
	 * experienced.  */
	tcp_flags[6] = flags_ptr[6];
	/* CWR: ongestion Window Reduced indicates that it received a TCP segment *
	 * with the ECE flag set and has responded in CCM (congestion control 	  *
	 * mechansim).    */
	tcp_flags[7] = flags_ptr[7];

	tcpheader.th_flags = 0;
	for (i=0; i<8; i++) {
		tcpheader.th_flags += (tcp_flags[i] << i);
	}
	// Window size (16 bits)
	tcpheader.th_win = htons (65535);
	// Urgent pointer (16 bits): 0 (only valid if URG flag is set)
	tcpheader.th_urp = htons (0);
	// TCP checksum (16 bits)
	tcpheader.th_sum = tcp_chksum (ipheader, tcpheader);
	/* Prep the packet to be sent. */
	/* First thing in the packet is the IPv4 header. */
	memcpy (packet, &ipheader, IP4_HEADER_LEN);
	/* Append TCP header to IP header. */
	memcpy ((packet + IP4_HEADER_LEN), &tcpheader, TCP_HEADER_LEN);
	/* Let kernel take care of ethernet header.  It is not revelant for our   *
	 * purposes. Pass destination IP to kernel.  To do this, we can create a  *
	 * struct in_addr for the destination IP and pass it to sendto().		  */
	memset (&sin, 0, sizeof (struct sockaddr_in));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ipheader.ip_dst.s_addr;
	/* Get a socket (Raw).  */
	if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror ("socket() failed ");
		exit (EXIT_FAILURE);
	}

	/* Socket configuration.  Tell it we will provide the IP(v4) 	  *
	 * header.																  */
	if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0) {
		perror ("setsockopt() failed to set IP_HDRINCL ");
		exit (EXIT_FAILURE);
	}

	/* Bind socket to specified interface. */
	if (setsockopt (sock, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof (ifr)) < 0) {
		perror ("setsockopt() failed to bind to interface ");
		exit (EXIT_FAILURE);
	}

	/* use sendto() to send the packet to the 'net. */ 
	if (sendto (sock, packet, IP4_HEADER_LEN + TCP_HEADER_LEN, 0, \
		(struct sockaddr *) &sin, sizeof (struct sockaddr)) < 0)  {
		perror ("sendto() failed ");
		exit (EXIT_FAILURE);
	}
	printf("packet sent!\n");

	/* Close socket descriptor. */
	close (sock);

	/* Free allocated memory. */
	free (packet);
	free (interface);
	free (target);
	free (source_ipaddr);
	free (dest_ipaddr);
	free (ip_flags);
	free (tcp_flags);
	return (EXIT_SUCCESS);
}
