#include "tcp.h"

/*******************************************************************************
 *  File: tcp.c
 *  Desc: Barebones TCP and IP Stacks.
 *  Current status: partial_handshake() takes care of sending a packet to the *
 *    target and getting the response.  It then calls get_packet_type() to    *
 *    determine whether the port is open or closed.
 ******************************************************************************/
 

/*  the linux kernel will send RST packet out right behind anything we 
 *  do that's not using the built-in TCP stack.  use iptables filtering
 *  to drop all these packets.
 *  system("iptables -A OUTPUT -p tcp -d 127.0.0.1 -s 127.0.0.1 --dport 80 --tcp-flags RST RST -j LOG");
 *  system("iptables -A OUTPUT -p tcp -d 127.0.0.1 -s 127.0.0.1 --dport 80 --tcp-flags RST RST -j DROP");
 *  <----- send packets over raw socket ----->
 *  system("iptables -A OUTPUT -p tcp -d 127.0.0.1 -s 127.0.0.1 --dport 80 --tcp-flags RST RST -j ACCEPT");
 * 
 */

int main(int argc, char **argv){
    system("iptables -A OUTPUT -p tcp -s 192.168.1.104 -d 192.168.1.113 --dport 80 --tcp-flags RST RST -j LOG");
    system("iptables -A OUTPUT -p tcp -s 192.168.1.104 -d 192.168.1.113  --dport 80 --tcp-flags RST RST -j DROP");
    struct target *t;
    t = (struct target *) malloc (sizeof(struct target));

    partial_handshake();  
    
    system("iptables --flush");
    return 0;
}

/***
 *  unsigned short int chksum(unsigned short int *addr, int length):
 *  computes a checksum for the IP+TCP header it is called on.
 ***/
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

/***
 *  unsigned short int build_chksum(struct ip ipheader, struct tcphdr tcpheader):
 *  generate the (correct) checksum for a given tcp header.
 *  But we need to build a pseudo-header, which will be included when we do the
 *  checksum calc.  It contains important info taken from fields in both the TCP
 *  and IP headers.  The pseudo-header (12 bytes) is followed by the actual TCP
 *  header up to the `options' field.
 *  Pseudo-header format specification:
 *                   +--------+--------+--------+--------+
 *                   |           Source Address          |
 *                   +--------+--------+--------+--------+
 *                   |         Destination Address       |
 *                   +--------+--------+--------+--------+
 *                   |  zero  |  PTCL  |    TCP Length   |
 *                   +--------+--------+--------+--------+
 ***/
unsigned short int build_chksum(struct ip ipheader, struct tcphdr tcpheader){

    unsigned short int sz;
    char buf[IP_MAXPACKET], offset_bytes;
    char *buf_p;
    int chksumsz = 0;
    buf_p = &buf[0];

    /* The general algorithm here is to use memcpy() to build each field of  *
     * the packet headers.  Then we update our convenience pointer and       *
     * checksum counter with the size of the field so we know the header     *
     * lengths when we go to compute the checksum.                           */

    memcpy(buf_p, &ipheader.ip_src.s_addr, sizeof(ipheader.ip_src.s_addr));
    buf_p += sizeof(ipheader.ip_src.s_addr); /* 4 bytes. */
    chksumsz += sizeof(ipheader.ip_src.s_addr);

    memcpy(buf_p, &ipheader.ip_dst.s_addr, sizeof(ipheader.ip_dst.s_addr));
    buf_p += sizeof(ipheader.ip_dst.s_addr); /* 4 bytes */
    chksumsz += sizeof(ipheader.ip_dst.s_addr);

    /* `reserved' field is set to all zeros. */
    *buf_p = 0; 
    buf_p++;
    chksumsz += 1;

    memcpy(buf_p, &ipheader.ip_p, sizeof(ipheader.ip_p));
    buf_p += sizeof(ipheader.ip_p); /* 1 byte. */
    chksumsz += sizeof(ipheader.ip_p);

    /* TCP Segment Length.  Length of both header and data in tcp segment. */
    sz = htons(sizeof(tcpheader));
    memcpy (buf_p, &sz, sizeof(sz));
    buf_p += sizeof(sz);
    chksumsz += sizeof(sz);
    
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
     * (this segment could have other duties, though), and this field      *
     * contains the sequence number the source is next expecting the       *
     * destination to send.   (32 bits)                                    */
    memcpy(buf_p, &tcpheader.th_ack, sizeof(tcpheader.th_ack));
    buf_p += sizeof(tcpheader.th_ack);
    chksumsz += sizeof(tcpheader.th_ack);

    /* The `data offset' field specifies number of 32-bit words of data in  *
     * our TCP header (must be multiple of 4).                              */
    offset_bytes = (tcpheader.th_off << 4) + tcpheader.th_x2;
    memcpy(buf_p, &offset_bytes, sizeof(offset_bytes));
    buf_p += sizeof(offset_bytes);
    chksumsz += sizeof(offset_bytes);

    /* Control bits (aka tcp flags)                                        *
     *  URG: indicates priority feature has been invoked on this segment,  *
     *  ACK: when set, this segment is an ACK packet.                      *
     *  PSH: sender of this segment wants data pushed asap to application. *
     *  RST: problem encoutered, reset connection.                         *
     *  SYN: this segment is a request to synch sequence numbers /         *
     *       establish a connection.                                       *
     *  FIN: sender of this segment is requesting to end the connection.]  */
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
     * 2 bytes.                                                              */
    *buf_p = 0; buf_p++;
    *buf_p = 0; buf_p++;
    chksumsz += 2;

    /* Urgent pointer field used in conjunction with URG control bit for     *
     * priority data transfer.  This field contains the sequence number of   *
     * the last byte of urgent data.                                         */
    memcpy(buf_p, &tcpheader.th_urp, sizeof(tcpheader.th_urp));
    buf_p += sizeof(tcpheader.th_urp);
    chksumsz += sizeof(tcpheader.th_urp);
    
    return compute_chksum((unsigned short int *)buf, chksumsz);
}

/***
 *  int build_tcp_packet(char *iface, int *flags_ptr):
 *  
 *  Construct a TCP packet with IP datagram header too.  
 *  TCP packet header format specification:
 *  0                   1                   2                   3   
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Source Port          |       Destination Port        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Sequence Number                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Acknowledgment Number                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Data |           |U|A|P|R|S|F|                               |
 * | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
 * |       |           |G|K|H|T|N|N|                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Checksum            |         Urgent Pointer        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Options                    |    Padding    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             data                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
 *  IP packet header format specification:
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Version|  IHL  |Type of Service|          Total Length         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Identification        |Flags|      Fragment Offset    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Time to Live |    Protocol   |         Header Checksum       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Source Address                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Destination Address                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Options                    |    Padding    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * IHL = Internet Header Length: header may contain a variable number of
 *       options, this field specfies the size of the header.  it's also
 *       a handy offset to use to access the data segment. Min value is 5
 *       (RFC791), which is length of 5*32 = 160 bits (20 bytes).  Being
 *       a 4-bit value, the max length is 15 words = 480 bits (60 bytes).
 * TOS = Precedence:0-2 Delay:3 Throughput:4 Reliability:5 Reserved:6,7
 * Flags = Reserved:0, Don't Fragment (DF):1, More Fragments (MF):2
 ***/
unsigned char *build_packet(unsigned char *packet, int *flags_ptr, char *source_ipaddr, char *dest_ipaddr, struct sockaddr_in *sin){
    int i;
    struct ip ipheader;
    struct tcphdr tcpheader;
    unsigned char *ip_flags, *tcp_flags;
    void *tmp;
    

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
    /* Type of Service (TOS): carries info for quality of service features    *
     * like priority datagrams. 1 byte.                                       */
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
     * datagram. The first fragment has an offset of zero.                    */
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
    tcpheader.th_sport = htons (31337);
    /* Destination port number (16 bits) */
    tcpheader.th_dport = htons (80);
    /* Sequence number (32 bits): 
     * If the SYN flag is set (1), then this is the initial sequence number.  *
     * The sequence number of the actual first data byte and the acknowledged *
     * number in the corresponding ACK are then this sequence number plus 1.  *
     * If the SYN flag is clear (0), then this is the accumulated sequence    *
     * number of the first data byte of this packet for the current session.  */
    tcpheader.th_seq = htonl (0);
    /* Acknowledgement number (32 bits): 0 in first packet of SYN/ACK         *
     * process. If the ACK flag is set then the value of this field is the    *
     * next sequence number that the receiver is expecting. This acknowledges *
     * receipt of all prior bytes (if any). The first ACK sent by each end    *
     * acknowledges the other end's initial sequence number itself, but no    *
     * data.  */
    tcpheader.th_ack = htonl (0);
    // Reserved (4 bits): Placeholders for TCP development.  Must be zero.
    tcpheader.th_x2 = 0;
    /* Data offset (4 bits): specifies the size of the TCP header in 32-bit   *
     * words. The minimum size header is 5 words and the maximum is 15 words  *
     * thus giving the minimum size of 20 bytes and maximum of 60 bytes,      *
     * allowing for up to 40 bytes of options in the header.  */
    tcpheader.th_off = TCP_HEADER_LEN / 4;

    /* Flag name: description */
    /* FIN: No more data from sender. */
    tcp_flags[0] = flags_ptr[0];
    /* SYN: Sync sequence numbers.  Only 1st packet sent from each end  *
     * should have this flag set.                                            */ 
    tcp_flags[1] = flags_ptr[1];
    /* RST: Reset the connection. */
    tcp_flags[2] = flags_ptr[2];
    /* PSH: Push function. Asks to push the buffered data to the receiving   *
     * device.                                                               */
    tcp_flags[3] = flags_ptr[3];
    /* ACK: indicates acknowledgment field is significant.  All regular      *
     * packets after the initial SYN packet sent by client should have this  *
     * flag set.                                                             */
    tcp_flags[4] = flags_ptr[4];
    // URG: Indicates the Urgent pointer field is significant.  */
    tcp_flags[5] = flags_ptr[5];
    /* ECE: (ECN-Echo) if (SYN), sender is ECN capable.  Else, congestion    * 
     * experienced.  */
    tcp_flags[6] = flags_ptr[6];
    /* CWR: ongestion Window Reduced indicates that it received a TCP segment *
     * with the ECE flag set and has responded in CCM (congestion control     *
     * mechansim).    */
    tcp_flags[7] = flags_ptr[7];

    tcpheader.th_flags = 0;
    for (i=0; i<8; i++) {
        tcpheader.th_flags += (tcp_flags[i] << i);
    }
    // Window size (16 bits)
    tcpheader.th_win = htons (65535);
    /* Urgent pointer (16 bits): 0 (only valid if URG flag is set) */
    tcpheader.th_urp = htons (0);
    /* TCP checksum (16 bits) */
    tcpheader.th_sum = build_chksum (ipheader, tcpheader);
    /* Prep the packet to be sent. */
    /* First thing in the packet is the IPv4 header. */
    memcpy (packet, &ipheader, IP4_HEADER_LEN);
    /* Append TCP header to IP header. */
    memcpy ((packet + IP4_HEADER_LEN), &tcpheader, TCP_HEADER_LEN);
    /* Let kernel take care of ethernet header.  It is not revelant for our   *
     * purposes. Pass destination IP to kernel.  To do this, we can create a  *
     * struct in_addr for the destination IP and pass it to sendto().         */
    memset (sin, 0, sizeof (struct sockaddr_in));
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = ipheader.ip_dst.s_addr;

    free (ip_flags);
    free (tcp_flags);
    return packet;
}

/***
 *  int partial_handshake(int *flags_arg):                                    *
 *  Creates a socket for the target and initiates a TCP three-way handshake.  * 
 *  1.  Send SYN packet to target.
 *  2.  Wait to recv from target
 *  3.  Decode packet type and determine whether the port is open or closed.aaaa
 ***/
int partial_handshake(int *flags_arg) {

    int status, sock, flags_ptr[] = {0, 0, 0, 0, 0, 0, 0, 0}, bytes_recvd = 0;
    const int on = 1;
    char *interface, *target_ipaddr, *source_ipaddr, *dest_ipaddr;
    unsigned char *probe_pkt, *response_pkt, *rst_pkt;
    struct addrinfo hints, *res;
    struct sockaddr_in  *ipv4, sin;
    socklen_t sin_len;
    struct ifreq ifr;
    void *tmp;
    char *ifce = "eth1";

    memcpy(flags_ptr, SYN_PACKET_FLAGS, sizeof(int)*8);
    /* Memory allocations  */
    /*  the initial SYN packet to send the targets way. IP_MAXPACKET = 65,535 */
    tmp = (unsigned char *) malloc (IP_MAXPACKET * sizeof (unsigned char));
    if (tmp != NULL) {
        probe_pkt = tmp;
    } else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array 'probe_pkt'.\n");
        exit (EXIT_FAILURE);
    }
    bzero(probe_pkt, IP_MAXPACKET); /* same as memset (syn_packet, 0, IP_MAXPACKET); */
    
    /*  the target's response. IP_MAXPACKET = 65,535 */    
    tmp = (unsigned char *) malloc (IP_MAXPACKET * sizeof (unsigned char));
    if (tmp != NULL) {
        response_pkt = tmp;
    } else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array 'response_pkt'.\n");
        exit (EXIT_FAILURE);
    }
    bzero(response_pkt, IP_MAXPACKET); /*same as memset (response_pkt, 0, IP_MAXPACKET); */
    
    tmp = (unsigned char *) malloc (IP_MAXPACKET * sizeof (unsigned char));
    if (tmp != NULL) {
        rst_pkt = tmp;
    } else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array 'rst_pkt'.\n");
        exit (EXIT_FAILURE);
    }
    bzero(rst_pkt, IP_MAXPACKET); /*same as memset (rst_pkt, 0, IP_MAXPACKET); */

    
    /* string for local network interface name (eth0, wlan0, etc.)  */
    tmp = (char *) malloc (40 * sizeof(char));
    if (tmp != NULL) {
        interface = tmp;
    } else {
        fprintf(stderr, "ERROR: Cannot allocate memory for array 'interface'.\n");
        exit(EXIT_FAILURE);
    }
    memset(interface, 0, 40);
    strcpy(interface, ifce);

    tmp = (char *) malloc (40 * sizeof(char));
    if (tmp != NULL) {
        target_ipaddr = tmp;
    } else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array 'target'.\n");
        exit(EXIT_FAILURE);
    }
    memset(target_ipaddr, 0, 40);

    tmp = (char *) malloc (16 * sizeof(char));
    if (tmp != NULL) {
        source_ipaddr = tmp;
    } else {
        fprintf(stderr, "ERROR: Cannot allocate memory for array 'source_ipaddr'.\n");
        exit(EXIT_FAILURE);
    }
    memset(source_ipaddr, 0, 16);

    tmp = (char *) malloc (16 * sizeof(char));
    if (tmp != NULL) {
        dest_ipaddr = tmp;
    } else {
        fprintf(stderr, "ERROR: Cannot allocate memory for array 'dest_ipaddr'.\n");
        exit(EXIT_FAILURE);
    }
    memset(dest_ipaddr, 0, 16);
    
    /* Now we create a socket and get the network interface to use SOCKET_RAW */
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        perror("socket() failed to get socket descriptor for using ioctl() ");
        exit(EXIT_FAILURE);
    }

    /* Use ioctl() to lookup interface. We NEED the ifr for SOCKET_RAW. */
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl() failed to find interface ");
        exit(EXIT_FAILURE);
    }

    printf("interface %i is %s\n", ifr.ifr_ifindex, interface);
    /* users IP needs to go here */
    print_ip(ifr.ifr_name, &source_ipaddr);
    printf("back in partial handshake ip is %s\n", source_ipaddr);
    //strcpy(source_ipaddr, "192.168.1.104");

    /* Destination URL or IPv4 address */
    strcpy(target_ipaddr, "192.168.1.113");

    /* Fill out hints for getaddrinfo(). */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = hints.ai_flags | AI_CANONNAME;

    // Resolve target using getaddrinfo().
    if ((status = getaddrinfo(target_ipaddr, NULL, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
        exit(EXIT_FAILURE);
    }
    ipv4 = (struct sockaddr_in *) res->ai_addr;
    tmp = &(ipv4->sin_addr);
    inet_ntop (AF_INET, tmp, dest_ipaddr, 16);
    freeaddrinfo(res);
    
    
    probe_pkt = build_packet(probe_pkt, flags_ptr, source_ipaddr, dest_ipaddr, &sin);
    
    sin_len = (socklen_t) sizeof(sin);
    /* Socket configuration.  Tell it we will provide the IPv4 header     */
    if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt() failed to set IP_HDRINCL ");
        exit(EXIT_FAILURE);
    }

    /* Bind socket to specified interface. */
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
        perror("setsockopt() failed to bind to interface ");
        exit(EXIT_FAILURE);
    }

    /* Send initial TCP Connection Establishment packet (SYN).  */
    if (sendto(sock, probe_pkt, IP4_HEADER_LEN + TCP_HEADER_LEN, 0, \
        (struct sockaddr *) &sin, sizeof(struct sockaddr)) < 0)  {
        perror("sendto() failed on SYN ");
        exit(EXIT_FAILURE);
    }
    
    /* Recieve TCP Connection Establishment response packet.  If it is
     * a SYN/ACK, the port is open.  If it is a RST or no response, it 
     * is closed. */
    bytes_recvd = recvfrom(sock, response_pkt, IP_MAXPACKET, 0, (struct sockaddr *) &sin, &sin_len);
    if (bytes_recvd < 0) {
        perror("recvfrom() failed on SYN/ACK ");
        exit(EXIT_FAILURE);
    }
    printf("recvd %d bytes!\n", bytes_recvd);
    get_packet_type(&response_pkt);
    close(sock);
    free(probe_pkt);
    free(response_pkt);
    free(rst_pkt);
    free(interface);
    free(target_ipaddr);
    free(source_ipaddr);
    free(dest_ipaddr);
    return (EXIT_SUCCESS);
}

int get_packet_type(unsigned char **packet) {

    unsigned char flags;
    int flags_offset = 0x21;
    memcpy(&flags, ((*packet) + flags_offset), 1);
    if ((flags & SYNACK_MASK) == flags) {
        printf("port 80 is open BIAAAAATCH!\n");
        return 2;
    }
    else if ((flags & RSTACK_MASK) == flags) {
        printf("port 80 is closed!\n");
        return 1;
    }
    else {
        printf("port 80 is not known!\n");
        return 3;   
    }
}

void print_ip(char iface[], char **buffer) {
    char *cmd;
    cmd = (char *) malloc (sizeof(char) * 20);
    snprintf(cmd, 20, "ifconfig %s", iface);
    FILE *fp = popen(cmd, "r");
    if (fp) {
        char *p=NULL, *e; size_t n;
        while ((getline(&p, &n, fp) > 0) && p) {
            if (p = strstr(p, "inet addr:")) {
                p+=10;
                if (e = strchr(p, ' ')) {
                    *e='\0';
                    printf("PRINT IP: %s\n", p);
                    snprintf(*buffer, 20, "%s", p);
                }
            }
        }
    }
    free(cmd);
    pclose(fp);
    //return buffer;
}
