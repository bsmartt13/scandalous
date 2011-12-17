#include "target.h"


enum supported_scantypes 
{
	PING, SYN, TCP, UDP, FIN, NULLSCAN, XMAS
};

struct scan
{
	struct target *victim; /* { sockaddr_in *address, char *name, int type } */
	enum supported_scantypes scantype; /* */
	unsigned int flags; /* unimplemented */
	int sock; /* socket descriptor */
};



//function declarations
int parse_arguments(int argc, char **argv);
int parse_scantype(char *arg, enum supported_scantypes *type);
int parse_target(char *arg);
