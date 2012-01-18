#include "scan.h"

/*****
 *  File: scan.c
 *  Author: Bill Smartt <bsmartt13@gmail.com>
 *  Description: struct scan and everything it needs.
 *  Status: working
 *****/

/***
 * struct scan *allocate_scan():
 * allocates and zeroes out a scan struct on the heap.
 * returns a pointer into the heap where the new scan struct resides.
 ***/
struct scan *allocate_scan() {
    struct scan *s;
    void *tmp; /* do not free me!!! */
    
    tmp = (struct scan *) malloc ( sizeof (struct scan));
	if (tmp != NULL) s = tmp;
	else {
		fprintf (stderr, "ERROR: unable to allocate memory for `struct scan *s`. (allocate_target())\n");
		exit (EXIT_FAILURE);
	}
	memset (s, 0, sizeof(struct scan));
    return s;
}

