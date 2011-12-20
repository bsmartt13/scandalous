#include "parse.h"
#include "parse_target.h"

/*******************************************************************************
 *  File: parse.c
 *  Author: Bill Smartt <bsmartt13@gmail.com>
 *  Description: The main parsing functionality is contained in this file.
 *  Status: Implemented.
 ******************************************************************************/

/*  int parse_arguments(int argc, char **argv):
 *  Parses the entire command line argument.  as it finds the options, it calls 
 *  helper functions to parse individual arguments.  Parsing the target IP is more
 *  complex, so it sits in it's own file, parse_target.c|h.  
 */
int parse_arguments(int argc, char **argv){
	int index = 0, valid_args = 0, targets_found = 0;
	char *scan_op = NULL, *target_op = NULL;
	int c;
	struct target *t;
	struct scan *s;
	struct sockaddr_in *target_sockaddr;
	
	t = (struct target *) malloc (sizeof (struct target));
	s = (struct scan *) malloc (sizeof (struct scan));

	target_sockaddr = (struct sockaddr_in *) malloc (sizeof (struct sockaddr_in));
	s->victim = t;
	t->address = target_sockaddr;
	
	while ((c = getopt (argc, argv, "s:t:")) != -1)
		switch (c){
			case 's':
				scan_op = optarg;
				valid_args++;
				break;
			case 't':
				target_op = optarg;
				valid_args++;
				break;
			case '?':
				if (optopt == 's')
					fprintf (stderr, "Option -%c requires an argument (scan \
						type).\n", optopt);
				else if (optopt == 't'){
					fprintf(stderr, "Option -%c requires an argument (ip \
						address in for x.x.x.x)", optopt);
				}
				else if (isprint (optopt))
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
				return -1;
			default:
				abort ();
	}
	printf ("scantype = %s target = %s\n", scan_op, target_op);
	for (index = optind; index < argc; index++)
		printf ("Non-option argument %s\n", argv[index]);

	enum supported_scantypes *stype = (enum supported_scantypes *) \
		malloc (sizeof(enum supported_scantypes));
	if (valid_args > 0){
		parse_scantype(scan_op, stype);
		targets_found = parse_target(target_op, &t);
		printf("\ntargets_found back in parse_arguments(): %d\n", targets_found);
	}
	
	return valid_args;
}

/*  int parse_scantype(char *arg, enum supported_scantypes *type):
 *  Parses just the scantype argument.
 *  note: not all scan types are supported yet.
 */
int parse_scantype(char *arg, enum supported_scantypes *type){

	char base = arg[0];
	switch (base){
		case 'P':
			printf("scantype: ping scan\n");
			*type = PING;
			return 0;
		case 'S':
			printf("scantype: stealth scan\n");
			*type = SYN;
			return 0;
		case 'T':
			printf("scantype: tcp connect scan\n");
			*type = TCP;
			return 1;
		case 'U':
			printf("scantype: udp scan\n");
			*type = UDP;
			return 2;
		case 'F':
			printf("scantype: fin scan\n");
			*type = FIN;
			return 3;
		case 'N':
			printf("scantype: null scan\n");
			*type = NULLSCAN;
			return 4;
		case 'X':
			printf("scantype: xmas scan\n");
			*type = XMAS;
			return 5;
		default:
			printf("scantype: unknown scan type.\n");
			type = NULL;
			return -1;
	}
}

/*  int parse_target(char *arg, struct target *ret):
 *  Parses the IP list from command line args.  Finds the list delimiter ",", 
 *  the range delimiter "-", and wildcards "*".  It calls the functions to deal with each of these
 *  if it finds any.
 */
int parse_target(char *arg, struct target **ret){
	char **target_list;
	int targets_found = 0;
	unsigned int code = 0; /* 1 = list, 2 = range, 3 = wildcard. */
	int count = 0, i = 0;
	int wc_position = -1;
	/*
	const char range_indicator[] = "-";
	const char wildcard_indicator[] = "*";
	*/
	
	if (strstr(arg, ",") != NULL){
		code += 1;
	}
	if (strstr(arg, "-") != NULL){
		code += 2;
	}
	if (strstr(arg, "*") != NULL){
		code += 4;
	}
	
	count = count_list_items(arg);
	if (count > 1){
		target_list = parse_list(arg);
		for (i = 0; i < count; i++){
			printf("target found: %s (parse_target())\n", target_list[i]);
		}
	} else{
		printf("Only found 1 target: %s\n", arg);
	}
	wc_position = find_wc_position(arg);
	printf("found a wildcard at position: %d", wc_position);
	if (wc_position != -1){
		target_list = build_targets_from_wc(arg, wc_position, &targets_found);
	}
	
	if (target_list){ 
		printf("found %d targets total.  here they are:\n", targets_found);
		for (i = 0; i < targets_found; i++){
			printf("target %d: %s\n", i, target_list[i]);
		}
	}
	
	return count;
}

/*  struct target buildTarget(char *target_op):
 *  Sets up a default target.
 */
struct target buildTarget(char *target_op){

	struct target t;
	struct sockaddr_in s;
	t.address = &s;
	t.port = 80;
	s.sin_family = AF_INET;
	s.sin_addr.s_addr = inet_addr(target_op);
	return t;
}

int main (int argc, char **argv){
	printf("-----------------------------------------\n");
	printf("parse.c\n");
	printf("-----------------------------------------\n\n");
	
	parse_arguments(argc, argv);
	
	return 0;
}
