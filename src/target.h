#include <sys/socket.h>  /* socket(), connect() */
#include <arpa/inet.h>

#define MAX_TARGETS 256

/* scan states */
#define WAITING -1
#define READY 0

#define RUNNING 1
#define DONE 2

/* types of targets */
#define _TARGET 1
#define _SELF 0
#define _OTHER -1

/* This list is the result of some brilliant work by Fyodor in his "Scanning the
 * Internet" presentation (Summer 2008).
 */
static const unsigned short top20_tcp_ports[] = {	80,		/* HTTP */
													23,		/* Telnet */
													443,	/* HTTPS */
													21,		/* FTP */
													22,		/* SSH */ 
													25,		/* SMTP */
													3389,	/* ms-term-serv */
													110,	/* POP3 */
													445,	/* Microsoft-DS */
													139,	/* NetBIOS-SSN */
													143,	/* IMAP */
													53,		/* DNS */
													135,	/* MySQL */
													3306,	/* HTTP-Proxy */
													8080,	/* PPTP */
													1723,	/* RPCBind */
													111,	/* POP3S */
													995,	/* IMAPS */
													5900,	/* VNC */
												};

struct host
{
	struct sockaddr_in *addr;
	char *ipaddr;
	unsigned short *ports;
	unsigned int num_ports;		// length of ports array
	unsigned int host_type; 
	
	
};

struct target
{
	struct host *source_h;
	struct host *dest_h;

	int status;
};

/* target.c function declarations */
struct target *allocate_target();


