#include <stdio.h>		/* f|s|v|printf(), scanf() fflush() stdin/out/err, NULL, size_t */
#include <stdlib.h>		/* malloc(), calloc(), free(), exit(), */
#include <unistd.h>		/* close() */
#include <string.h>		/* str(n)cpy(), strlen(), memcmp/cpy/set() strtok(), strstr() */
#include <netdb.h>		/* for addrinfo */
#include <sys/types.h>	/* for socket() , pthread, time_t*/
#include <sys/socket.h>	/* socket() */
#include <netinet/in.h>	/* IPPROTO_IP + IPPROTO_TCP constants */
#include <netinet/ip.h>	/* struct ip and IP_MAXPACKET */
#define __FAVOR_BSD		/* prefer BSD style packet headers */
#include <netinet/tcp.h>	/* struct tcphdr */
#include <arpa/inet.h>	/* inet_pton(), inet_ntop() */
#include <sys/ioctl.h>	/* ioctl() */
#include <bits/ioctls.h>	/* defines `request' argument for ioctl();. */
#include <net/if.h>		/* struct ifreq */
//#include <time.h> 		/* clock(), time(), localtime(), difftime() clock_t */
#include <errno.h>		/* stderr, errno, perror() */


// Constants
#define IP4_HEADER_LEN 20         /* length of a IPv4 header in bytes */
#define TCP_HEADER_LEN 20         /* length of a TCP header in bytes. */

// Function declarations
unsigned short int compute_chksum(unsigned short int *addr, int length);
unsigned short int tcp_chksum(struct ip ipheader, struct tcphdr tcpheader);
int build_tcp_packet(char *iface, int *flags_ptr);
