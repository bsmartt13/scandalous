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

/* These are used to identify tcp packet control bits (flags).  */
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

/* these are used for the tcpheader struct. */
                  /*               [FIN, SYN, RST, PSH, ACK, URG, ECE, CWR] */
static int SYN_PACKET_FLAGS[] =    { 0,   1,   0,   0,   0,   0,   0,   0 };
static int URGSYN_PACKET_FLAGS[] = { 0,   1,   0,   0,   0,   0,   0,   0 };
static int ACK_PACKET_FLAGS[] =    { 0,   0,   0,   0,   1,   0,   0,   0 };
static int SYNACK_PACKET_FLAGS[] = { 0,   1,   0,   0,   1,   0,   0,   0 };
static int FIN_PACKET_FLAGS[] =    { 1,   0,   0,   0,   0,   0,   0,   0 };
static int URGACK_PACKET_FLAGS[] = { 0,   0,   0,   0,   1,   1,   0,   0 };
static int RST_PACKET_FLAGS[] = { 0,   0,   1,   0,   0,   0,   0,   0 };

// Function declarations
unsigned short int compute_chksum(unsigned short int *addr, int length);
unsigned short int build_chksum(struct ip ipheader, struct tcphdr tcpheader);
unsigned char *build_packet(unsigned char *packet, int *flags_ptr, char *source_ipaddr, char *dest_ipaddr, struct sockaddr_in *sin);
int partial_handshake();
int get_packet_type(unsigned char **packet);
void get_extern_ip(char iface[], char **buffer);
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
