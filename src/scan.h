#include "target.h" /* struct target */

#define MAX_TARGETS 256 /* NOT YET USED */

enum scan_type {
    PING_SCAN = 1, 
    SYN_SCAN = 2, 
    TCP_CONNECT_SCAN = 3, 
    UDP_SCAN = 4, 
    FIN_SCAN = 5, 
    NULL_SCAN = 6, 
    XMAS_SCAN = 7
};

struct scan {
    struct target *victim; /* { sockaddr_in *address, char *name, int type } */
    enum scan_type scan_type; /* */
    unsigned int flags; /* unimplemented */
    int sock; /* socket descriptor */
};

struct results {
    int *port_status;
    
};

struct scan *allocate_scan();

