//#include <stdio.h>      /* printf(), scanf() fflush() stdin/out/err, NULL, size_t */
//#include <stdlib.h>     /* malloc(), calloc(), free(), exit(), */
//#include <unistd.h>     /* close() */
//#include <string.h>     /* str(n)cpy(), strlen(), memcmp/cpy/set() strtok(), strstr() */
#include <netdb.h>      /* for addrinfo */
#include <sys/types.h>  /* for socket() , pthread, time_t*/
#include <sys/socket.h> /* socket() */
#include <netinet/in.h> /* IPPROTO_IP + IPPROTO_TCP constants */
#include <netinet/ip.h> /* struct ip and IP_MAXPACKET */
#define __FAVOR_BSD     /* prefer BSD style packet headers */
#include <netinet/tcp.h>    /* struct tcphdr */
#include <arpa/inet.h>  /* inet_pton(), inet_ntop() */
#include <sys/ioctl.h>  /* ioctl() */
#include <bits/ioctls.h>    /* defines `request' argument for ioctl();. */
#include <net/if.h>     /* struct ifreq */
//#include <time.h>         /* clock(), time(), localtime(), difftime() clock_t */
#include <errno.h>      /* stderr, errno, perror() */

#include "parse.h"

// Constants
#define IP4_HEADER_LEN 20         /* length of a IPv4 header in bytes */
#define TCP_HEADER_LEN 20         /* length of a TCP header in bytes. */

enum port_states
{
    PORT_OPEN = 1, PORT_FILTERED = 2, PORT_CLOSED = -1
};

enum packet_type
{
    SYN_PACKET = 1, SYNACK_PACKET = 2, RST_PACKET = 3, FIN_PACKET = 4 
};


#define FIN_MASK 0x1
#define SYN_MASK 0x2
#define RST_MASK 0x4
#define PSH_MASK 0x8
#define ACK_MASK 0x10
#define URG_MASK 0x20
#define ECE_MASK 0x40
#define CON_MASK 0x80

#define SYNACK_MASK 0x12
#define RSTACK_MASK 0x14

// Function declarations
unsigned short int compute_chksum(unsigned short int *addr, int length);
unsigned short int build_chksum(struct ip ipheader, struct tcphdr tcpheader);
unsigned char *build_packet(unsigned char *packet, int *flags_ptr, char *source_ipaddr, char *dest_ipaddr, struct sockaddr_in *sin);
int partial_handshake();
int get_packet_type(unsigned char **packet);
/***
 *
 * September 1981                                                          
 *                                            Transmission Control Protocol
 *                                                 Functional Specification
 * 
 *                               +---------+ ---------\      active OPEN  
 *                               |  CLOSED |            \    -----------  
 *                               +---------+<---------\   \   create TCB  
 *                                 |     ^              \   \  snd SYN    
 *                    passive OPEN |     |   CLOSE        \   \           
 *                    ------------ |     | ----------       \   \         
 *                     create TCB  |     | delete TCB         \   \       
 *                                 V     |                      \   \     
 *                               +---------+            CLOSE    |    \   
 *                               |  LISTEN |          ---------- |     |  
 *                               +---------+          delete TCB |     |  
 *                    rcv SYN      |     |     SEND              |     |  
 *                   -----------   |     |    -------            |     V  
 *  +---------+      snd SYN,ACK  /       \   snd SYN          +---------+
 *  |         |<-----------------           ------------------>|         |
 *  |   SYN   |                    rcv SYN                     |   SYN   |
 *  |   RCVD  |<-----------------------------------------------|   SENT  |
 *  |         |                    snd ACK                     |         |
 *  |         |------------------           -------------------|         |
 *  +---------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +---------+
 *    |           --------------   |     |   -----------                  
 *    |                  x         |     |     snd ACK                    
 *    |                            V     V                                
 *    |  CLOSE                   +---------+                              
 *    | -------                  |  ESTAB  |                              
 *    | snd FIN                  +---------+                              
 *    |                   CLOSE    |     |    rcv FIN                     
 *    V                  -------   |     |    -------                     
 *  +---------+          snd FIN  /       \   snd ACK          +---------+
 *  |  FIN    |<-----------------           ------------------>|  CLOSE  |
 *  | WAIT-1  |------------------                              |   WAIT  |
 *  +---------+          rcv FIN  \                            +---------+
 *   | rcv ACK of FIN   -------   |                            CLOSE  |  
 *   | --------------   snd ACK   |                           ------- |  
 *   V        x                   V                           snd FIN V  
 * +---------+                  +---------+                   +---------+
 * |FINWAIT-2|                  | CLOSING |                   | LAST-ACK|
 * +---------+                  +---------+                   +---------+
 *   |                rcv ACK of FIN |                 rcv ACK of FIN |  
 *   |  rcv FIN       -------------- |    Timeout=2MSL -------------- |  
 *   |  -------              x       V    ------------        x       V  
 *    \ snd ACK                 +---------+delete TCB         +---------+
 *     ------------------------>|TIME WAIT|------------------>| CLOSED  |
 *                              +---------+                   +---------+
 ***/
