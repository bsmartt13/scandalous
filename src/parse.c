#include "parse.h"


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
    t = (struct target *) malloc (sizeof(struct target));
	
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

	enum scan_type *stype = (enum scan_type *) \
		malloc (sizeof(enum scan_type));
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
int parse_scantype(char *arg, enum scan_type *type){

	char base = arg[0];
	switch (base){
		case 'P':
			printf("scantype: ping scan\n");
			*type = PING_SCAN;
			return 0;
		case 'S':
			printf("scantype: syn/stealth scan\n");
			*type = SYN_SCAN;
			return 0;
		case 'T':
			printf("scantype: tcp connect scan\n");
			*type = TCP_CONNECT_SCAN;
			return 1;
		case 'U':
			printf("scantype: udp scan\n");
			*type = UDP_SCAN;
			return 2;
		case 'F':
			printf("scantype: fin scan\n");
			*type = FIN_SCAN;
			return 3;
		case 'N':
			printf("scantype: null scan\n");
			*type = NULL_SCAN;
			return 4;
		case 'X':
			printf("scantype: xmas scan\n");
			*type = XMAS_SCAN;
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
	int list_size = 0;
	unsigned int code = 0; /* 1 = list, 2 = range, 3 = wildcard. */
	int count = 0, i = 0;
	int wc_position = 0;
	
	if (strstr(arg, ",") != NULL) code += 1;
	if (strstr(arg, "-") != NULL) code += 2;
	if (strstr(arg, "*") != NULL) code += 4;
	count = count_list_items(arg);
	
	if (count > 1){
		target_list = parse_list(arg);
		for (i = 0; i < count; i++){
			printf("target found: %s (parse_target())\n", target_list[i]);
		}
	} else {
		printf("Only found 1 target: %s\n", arg);
	}

	wc_position = find_wc_position(arg);
	if (wc_position != -1){
	#ifdef DEBUG
        printf("found a wildcard at position: %d", wc_position);
    #endif
   		target_list = build_targets_from_wc(arg, wc_position, &list_size);
	}
	
	if (target_list) {
		printf("found %d targets total.  here they are:\n", list_size);
		for (i = 0; i < list_size; i++){
			printf("target %d: %s\n", i, target_list[i]);
		}
		count = list_size;
	}
	return count;
}

int main (int argc, char **argv){
	printf("-----------------------------------------\n");
	printf("parse.c\n");
	printf("-----------------------------------------\n\n");
	
	parse_arguments(argc, argv);
	
	return 0;
}


/* target */

const char wildcard_delim[] = "*";
const char list_delim[] = ",";

/*  int split_target_list(char *arg, char **ret):
 *  Splits list at the seperator ",".  returns an array of the IP address in the
 *  function arg char **ret.  returns the number of targets found.
 */ 
int split_target_list(char *arg, char **ret){

	int count = count_list_items(arg);
	printf("count is: %d (list_targets)\n",count);
	printf("arg is %s\n", arg);
	

	char *token;
	char *running;
	int targs_found = 0;
	
	running = strdup(arg); //must not free this memory until target ip is saved to struct target.
	token = strsep(&running, list_delim);
	ret[targs_found] = (char *) malloc (sizeof (char) * strlen(token));
	ret[targs_found++] = token;
#ifdef DEBUG
	printf("new target found: %s\n", ret[targs_found - 1]);
#endif
	for(; targs_found < count && token != NULL; targs_found++){
		token = strsep(&running, list_delim);
		ret[targs_found] = (char *) malloc (sizeof (char) * strlen(token));
		ret[targs_found] = token;
	#ifdef DEBUG
		printf("new target found: %s\n", ret[targs_found]);
	#endif
	}
	return targs_found;
}

/*  int count_list_items(char *arg):
 *  counts the number of items in a list seperated by ",".
 */
int count_list_items(char *arg){
	int count = 1, index = 0;
	while (arg[index] != '\0'){
		if (arg[index++] == ',')
			count++;
	}
	return count;
}

/*  char **parse_list(char *arg):
 *  ensures the list is properly parsed.
 */
char **parse_list(char *arg){
	int counted = 0, found = 0;
	char **parsed;
	counted = count_list_items(arg);
	parsed = (char **) malloc (sizeof (char *) * counted);
	found = split_target_list(arg, parsed);
	return parsed;
}

/*  int find_wildcard(char *arg):
 *  Splits list at the seperator ",".  returns an array of the IP address in the
 *  function arg char **ret.  returns the number of targets found.
 */
int find_wildcard(char *arg){
	if (strstr(arg, wildcard_delim)) {
		printf("Wildcard found");
		return 1;
	}
	return 0;
}

/*  int find_wc_position(char *arg):
 *  finds the array index of the "*" wildcard.
 */
int find_wc_position(char *arg) {
	int wc_pos = -1, index = 0;
	while (arg[index] != '\0'){
		if (arg[index] == '*')
			wc_pos = index;
		index++;
	}
	return wc_pos;
}

/*  int find_wc_position(char *arg):
 *  finds the octet containing the "*" wildcard.
 */
int find_wc_quad(char *arg){
	int current_quad = 0, index = 0;
	while (arg[index] != '\0'){
		if (arg[index] == '.'){
			current_quad++;
		}
		else if (arg[index] == '*'){
			return current_quad;
		}
		index++;
	}
	return -1;
}

/*  char **build_targets_from_wc(char *arg, int pre_wc_chars):
 *  generates all of the actual IPs matching the wildcarded IP.
 */
char **build_targets_from_wc(char *arg, int pre_wc_chars, int *generated){
	char **ret;
	int current_ip = 0;
	int valid_targets = 0;
	ret = (char **) malloc (sizeof (char *) * 256);
	
	/* This is a safe use of sprintf.  The for loop puts a ceiling on the  
	 * value being printed [0 < x < 256], and there will always be enough
	 * space for a 3 digit value in the string.
	 */
	for(;current_ip < 256; current_ip++){ /* for each new IP in subnet */
		ret[current_ip] = (char *) malloc (sizeof (char ) * 16);
		memcpy(ret[current_ip], arg, sizeof(char) * pre_wc_chars);
		sprintf(&ret[current_ip][pre_wc_chars], "%d", current_ip);
		valid_targets++;
		#ifdef DEBUG
		printf("generated new ip from wildcarded target: %s (#%d)\n", ret[current_ip], valid_targets);
		#endif
	}
	memcpy(generated, &current_ip, sizeof(int));
	return ret;
}
