#include "parse.h"

/*  File: target.c
 *  Author: Bill Smartt <bsmartt13@gmail.com>
 *  Description: The main scanning functionality
 *  Status: Not yet implemented.
 */

struct target *allocate_target(char *iface) {

	void *tmp;
	struct target *t;
	struct host *self, *other;
	
	tmp = (struct target *) malloc ( sizeof (struct target));
	if (tmp != NULL) {
		t = tmp;
	} else {
		fprintf (stderr, "ERROR: unable to allocate memory for target. (allocate_target())\n");
		exit (EXIT_FAILURE);
	}
	memset (t, 0, sizeof(struct target));
	
	tmp = (struct host *) malloc (sizeof (struct host));
	if (tmp != NULL) {
		self = tmp;
	} else {
		fprintf (stderr, "ERROR: unable to allocate memory for host (1). (allocate_target())\n");
		exit (EXIT_FAILURE);
	}
	memset (self, 0, sizeof(struct host));
    self->host_type = _SELF;
    t->source_h = self;
	
	tmp = (struct host *) malloc (sizeof (struct host));
	if (tmp != NULL) {
		other = tmp;
	} else {
		fprintf (stderr, "ERROR: unable to allocate memory for other (1). (allocate_target())\n");
		exit (EXIT_FAILURE);
	}
	memset (other, 0, sizeof(struct host));
	other->host_type = _TARGET;
	t->dest_h = other;
	
	return t;
}

/***
 *  void get_extern_ip(char iface[], char **buffer):
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

int main(int argc, char **argv) {

	struct target *t;
	t = allocate_target("eth1");
	
	t->source_h->ipaddr = (char *) malloc (sizeof (char) * 16);
	t->source_h->ipaddr = "192.168.100.104";

	printf("t->src->ip: %s\n", t->source_h->ipaddr);
	return 0;
}
