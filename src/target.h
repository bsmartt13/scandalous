#include <sys/socket.h>  /* socket(), connect() */
#include <netinet/in.h> /* struct sockaddr_in */
#include <arpa/inet.h> /* inet_pton() */
#include <stdlib.h> /* malloc(), exit() */
#include <stdio.h> /* printf() family, popen */
#include <string.h> /* memset(), strstr(), strchr() */
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
#define MAX_TARGETS 256
/* port statuses used to keep track of what has and hasn't been scanned */
#define _WAITING_ 0
#define _READY_ 1
#define _RUNNING_ 2
#define _DONE_ 3
/* port states */
#define __UNKNOWN -1 /* all ports start in this state. */
#define __CLOSED 0
#define __OPEN 1
#define __FILTERED 2
/* types of targets */
#define _TARGET 1
#define _SELF 0
#define _OTHER -1
/* Protocols */
#define _TCP 1
#define _UDP 2 /* not used yet */
#define _ICMP 3 /* not used yet */
#define TOP20_PORTS_LEN 20
/* Thanks Fyodor!  This list is from his book `nmap network scanning'. */
static const unsigned short top20_tcp_ports[] = {
                        80,     /* HTTP */
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
                        135,    /* MSRPC */
                        3306,   /* MySQL */
                        8080,   /* HTTP Proxy */
                        1723,   /* PPTP */
                        111,    /* RPCBind */
                        995,    /* POPS */
                        993,    /* IMAPS */
                        5900,   /* VNC */
};
struct target {
    struct host *source_h;
    struct host *dest_h;
    char *interface;
    int status;
};
struct host {
    struct sockaddr_in *addr_in;
    struct plist *ports_pl;
    char *ipaddr;
    unsigned int host_type;
};
struct plist {
    unsigned short *ports;
    int *status;
    int *states;
    int protocol;
    int length;
};
/* target.c function declarations */
struct target *allocate_target(char *iface);
struct plist *construct_plist(unsigned short *port_list, int len, int proto);
struct host *construct_host(struct host *h, int htype, char *addr, unsigned short *port_list, int port_list_len);
void get_local_ip(char iface[], char **buffer, size_t buflen);
int target_test(int argc, char **argv);
