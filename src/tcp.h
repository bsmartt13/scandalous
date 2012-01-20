#include <netdb.h>      /* for addrinfo */
#include <sys/types.h>  /* for socket() */
#include <sys/socket.h> /* more socket() */
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
/* Copyright (c) 2012, Bill Smartt
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of this program nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#define IP4_HEADER_LEN 20         /* length of a IPv4 header in bytes */
#define TCP_HEADER_LEN 20         /* length of a TCP header in bytes. */

enum port_states {
    PORT_OPEN = 1, PORT_FILTERED = 2, PORT_CLOSED = -1
};

enum packet_type {
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
