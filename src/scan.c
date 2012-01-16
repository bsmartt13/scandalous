#include "parse.h"

/*  File: scan.c
 *  Author: Bill Smartt <bsmartt13@gmail.com>
 *  Description: The main scanning functionality
 *  Status: Not yet implemented.
 struct scan
{
    struct target *victim;
    enum scan_type scantype; 
    unsigned int flags; unimplemented 
    int sock;
};

*/

struct scan *allocate_scan() {
    struct scan *s;
    void *tmp;
    
    tmp = (struct scan *) malloc ( sizeof (struct scan));
	if (tmp != NULL) {
		s = tmp;
	} else {
		fprintf (stderr, "ERROR: unable to allocate memory for `struct scan *s`. (allocate_target())\n");
		exit (EXIT_FAILURE);
	}
	memset (s, 0, sizeof(struct scan));
    
    return *s;

}
int main (int argc, char **argv) {
	parse_arguments(argc, argv);
	printf("scan.c\n");
	return 0;
}


