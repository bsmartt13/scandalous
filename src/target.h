#include <sys/socket.h>  /* socket(), connect() */
#include <arpa/inet.h>

struct target
{
	struct sockaddr_in *address;
	char *addr_str; /* string form of address */
	unsigned short port;
	char *name;
	int status;
};


