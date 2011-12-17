#include "scan.h"

//implementations
int parse_arguments(int argc, char **argv) {
	int index = 0, valid_args = 0;
	char *scan_op = NULL, *target_op = NULL;
	int c;
	struct target *t;
	struct scan *s;
	
	t = (struct target *) malloc (sizeof (struct target *));
	s = (struct scan *) malloc (sizeof (struct scan *));
	s->victim = t;
	memset(t->address, 0, sizeof(struct sockaddr_in));


	while ((c = getopt (argc, argv, "s:t:")) != -1)
		switch (c) {
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
				else if (optopt == 't') {
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
		malloc (sizeof(enum supported_scantypes *));
	if (valid_args > 0)
		parse_scantype(scan_op, stype);
		
	t->port = 80; /* TODO IMPORTANT implement port selection*/
	t->address.sin_family = AF_INET;
	t->address.sin_addr.s_addr = inet_addr(target_op);
	t->address.
	free(t);
	free(s);
	return valid_args;
}

int parse_scantype(char *arg, enum supported_scantypes *type) {

	char base = arg[0];
	switch (base) {
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

int parse_target(char *arg) {
	return 0;
}

int main (int argc, char **argv) {
	parse_arguments(argc, argv);
	return 0;
}


