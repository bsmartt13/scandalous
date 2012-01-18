#include <sys/socket.h>  /* socket(), connect() */
#include <netinet/in.h> /* struct sockaddr_in */
#include <arpa/inet.h> /* inet_pton() */
#include <stdlib.h> /* malloc(), exit() */
#include <stdio.h> /* printf() family, popen */
#include <string.h> /* memset(), strstr(), strchr() */

#define MAX_TARGETS 256

/* scan states */
#define WAITING -1
#define READY 0

#define RUNNING 1
#define DONE 2

/* types of targets */
#define _TARGET 1
#define _SELF 0
#define _OTHER -1

#define _TCP 1
#define _UDP 2 /* not used yet */
#define _ICMP 3 /* not used yet */

#define TOP20_PORTS_LEN 20
/* This list is the result of some brilliant work by Fyodor in his "Scanning the
 * Internet" presentation (Summer 2008). Thanks Fyodor!
 */
static const unsigned short top20_tcp_ports[] = {   80,     /* HTTP */
                        23,     /* Telnet */
                        443,    /* HTTPS */
                        21,     /* FTP */
                        22,     /* SSH */ 
                        25,     /* SMTP */
                        3389,   /* ms-term-serv */
                        110,    /* POP3 */
                        445,    /* Microsoft-DS */
                        139,    /* NetBIOS-SSN */
                        143,    /* IMAP */
                        53,     /* DNS */
                        135,    /* MySQL */
                        3306,   /* HTTP-Proxy */
                        8080,   /* PPTP */
                        1723,   /* RPCBind */
                        111,    /* POP3S */
                        995,    /* IMAPS */
                        5900,   /* VNC */
};
struct target
{
    struct host *source_h;
    struct host *dest_h;
    char *interface;
    int status;
};
struct host
{
    struct sockaddr_in *addr_in;
    struct plist *ports_pl;
    char *ipaddr;
    unsigned int host_type;
};
struct plist
{
    unsigned short *ports;
    int protocol;
    int length;
};

/* target.c function declarations */
struct target *allocate_target(char *iface);
struct plist *construct_plist(unsigned short *port_list, int len, int proto);
struct host *construct_host(struct host *h, int htype, char *addr, unsigned short *port_list, int port_list_len);
void get_local_ip(char iface[], char **buffer, size_t buflen);
int target_test(int argc, char **argv);
