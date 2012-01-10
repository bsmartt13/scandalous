#include "target.h"


#define MAX_TARGETS 256

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

struct results
{
	int *port_status;
	
};
