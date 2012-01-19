#include "target.h"
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
 * 4. Neither the name of this program nor the names of its contributors
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

/*****
 *  File: target.c
 *  Author: Bill Smartt <bsmartt13@gmail.com>
 *  Description: The main scanning functionality
 *  Status: working
 *****/

struct target *allocate_target(char *iface) {
	void *tmp; /* don't you dare free() this shit */
	struct target *t;
	struct host *self, *other;

	tmp = (struct target *) malloc ( sizeof (struct target));
	if (tmp != NULL) {
		t = tmp;
	} else {
		fprintf (stderr, "ERROR: unable to allocate memory for \
		    target. (allocate_target())\n");
		exit (EXIT_FAILURE);
	}
	memset (t, 0, sizeof(struct target));
	tmp = (struct host *) malloc (sizeof (struct host));
	if (tmp != NULL) {
		self = tmp;
	} else {
		fprintf (stderr, "ERROR: unable to allocate memory for \
		    host (1). (allocate_target())\n");
		exit (EXIT_FAILURE);
	}
	memset (self, 0, sizeof(struct host));
    self->host_type = _SELF;
    t->source_h = self;
	tmp = (struct host *) malloc (sizeof (struct host));
	if (tmp != NULL) {
		other = tmp;
	} else {
		fprintf (stderr, "ERROR: unable to allocate memory for \
		    other (1). (allocate_target())\n");
		exit (EXIT_FAILURE);
	}
	memset (other, 0, sizeof(struct host));
	tmp = (char *) malloc (sizeof(iface));
	if (tmp != NULL) {
	    t->interface = tmp;
	} else {
	    fprintf (stderr, "ERROR: unable to allocate memory for struct \
	        target->interface. (allocate_target())\n");
	    exit(EXIT_FAILURE);
	}
	other->host_type = _TARGET;
	t->dest_h = other;
	memcpy(t->interface, iface, sizeof(iface));
	
	return t;
}

struct plist *construct_plist(unsigned short *port_list, int len, int proto) {
    struct plist *pl;
    void *tmp;
    int i;
    
    tmp = (struct plist *) malloc (sizeof (struct plist));
    if (tmp != NULL) pl = tmp;
    else {
        fprintf (stderr, "ERROR: unable to allocate memory for struct \
            plist (allocate_plist())\n");
        exit (EXIT_FAILURE);
    }
    tmp = (unsigned short *) malloc (sizeof (unsigned short) * len);
    if (tmp != NULL) pl->ports = tmp;
    else {
        fprintf (stderr, "ERROR: unable to allocate memory for unsigned  \
            short *ports (allocate_plist())\n");
        exit (EXIT_FAILURE);
    }
    tmp = (int *) malloc (sizeof (int) * len);
    if (tmp != NULL) pl->status = tmp;
    else {
        fprintf (stderr, "ERROR: unable to allocate memory for int  \
            *status (allocate_plist())\n");
        exit (EXIT_FAILURE);
    }    
    tmp = (int *) malloc (sizeof (int) * len);
    if (tmp != NULL) pl->states = tmp;
    else {
        fprintf (stderr, "ERROR: unable to allocate memory for int  \
            *states (allocate_plist())\n");
        exit (EXIT_FAILURE);
    }
    memcpy (pl->ports, port_list, len * sizeof(unsigned short));
    pl->length = len;
    pl->protocol = proto;
    for (i=0; i<len; i++) {
        pl->states[i] = __UNKNOWN;
        pl->status[i] = _WAITING_;
    }
        
    return pl;
}

/***
 * void setopt_host(struct host *h,...:
 * sets up a host.  first port in plist is added to sockaddr_in
 * h: pointer to the host we're configuring.
 * htype: the host type (see target type macro target.h)
 * addr: pointer to string form ip address
 ***/
struct host *construct_host(struct host *h, int htype, char *addr, unsigned short *port_list, int port_list_len) {
    struct sockaddr_in *host_in;
    void *tmp; /* don't you dare free() this shit! */
    /* allocate struct host */
	tmp = (struct sockaddr_in *) malloc (sizeof(struct sockaddr_in));
	if (tmp != NULL) {
	    host_in = tmp;
	} else {
	    fprintf (stderr, "ERROR: unable to allocate memory for struct \
	        struct sockaddr_in. (construct_host())\n");
	    exit(EXIT_FAILURE);
	}
    /* allocate host->addr */
    tmp = (char *) malloc ( (strlen (addr) + 1) * sizeof(char) );
	if (tmp != NULL) {
	    h->ipaddr = tmp;
	} else {
	    fprintf (stderr, "ERROR: unable to allocate memory for struct \
	        h->ipaddr. (construct_host())\n");
	    exit(EXIT_FAILURE);
	}
    h->ports_pl = construct_plist(port_list, port_list_len, _TCP);
    host_in->sin_family = AF_INET;
    host_in->sin_port = htons(h->ports_pl->ports[0]);
    inet_pton(AF_INET, (const char *) addr, &(host_in->sin_addr));
    h->addr_in = host_in;
    memcpy (h->ipaddr, addr, strlen(addr) + 1);
    h->host_type = htype;
    
    return h;
}

/***
 *  void get_local_ip(char iface[], char **buffer):
 *  calls the bash command `ifconfig <iface>` and pulls the external ip it finds
 ***/
void get_local_ip(char iface[], char **buffer, size_t buflen) {
    char *cmd;
    cmd = (char *) malloc (sizeof(char) * 20);
    snprintf(cmd, 20, "ifconfig %s", iface);
    FILE *fp = popen(cmd, "r");
    if (fp) {
        char *p = NULL, *e; 
        size_t n;
        while ((getline(&p, &n, fp) > 0) && p) {
            if (p = strstr(p, "inet addr:")) {
                p+=10;
                if (e = strchr(p, ' ')) {
                    *e='\0';
                    printf("PRINT IP: %s\n", p);
                    snprintf(*buffer, buflen, "%s", p);
                }
            } else {
                perror("get_extern_ip() failed to get external ip using `ifconfig <iface>` ");
                exit(EXIT_FAILURE);
            }
        }
    }
    free(cmd);
    pclose(fp);
}

int target_test(int argc, char **argv) {

	struct target *t;
	t = allocate_target("eth1");
	
	t->source_h->ipaddr = (char *) malloc (sizeof (char) * 16);
	t->source_h->ipaddr = "192.168.100.104";

	printf("t->src->ip: %s\n", t->source_h->ipaddr);
	return 0;
}
