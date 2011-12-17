#include <stdio.h> /* printf(), fprintf() */
#include <ctype.h> /*  isprint() macro */
#include <string.h> /* strtok_r() bzero(), bcopy() */
#include <stdlib.h> /* atoi(), exit() */
#include <unistd.h> /* close() */
#include <sys/socket.h>  /* socket(), connect() */
/* #include <netinet/in.h> */

struct target
{
	struct sockaddr_in *address;
	char *addr_str; /* string form of address */
	unsigned short port;
	char *name;
	int status;
};


