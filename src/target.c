#include "parse.h"

/*  File: target.c
 *  Author: Bill Smartt <bsmartt13@gmail.com>
 *  Description: The main scanning functionality
 *  Status: Not yet implemented.
 */

struct target *allocate_target() {

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
	t->source_h = self;
	
	tmp = (struct host *) malloc (sizeof (struct host));
	if (tmp != NULL) {
		other = tmp;
	} else {
		fprintf (stderr, "ERROR: unable to allocate memory for other (1). (allocate_target())\n");
		exit (EXIT_FAILURE);
	}
	memset (other, 0, sizeof(struct host));
	t->dest_h = other;
	
	return t;
}


int main(int argc, char **argv) {

	struct target *t;
	t = allocate_target();
	
	t->source_h->ipaddr = (char *) malloc (sizeof (char) * 16);
	t->source_h->ipaddr = "192.168.100.100";

	printf("t->src->ip: %s\n", t->source_h->ipaddr);
	return 0;
}
