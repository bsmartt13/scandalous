#include <stdio.h> /* printf(), fprintf() */
#include <ctype.h> /*  isprint() macro */
#include <string.h> /* strtok_r() bzero(), bcopy() strdup() */
#include <stdlib.h> /* atoi(), exit() */
#include <unistd.h> /* close() */

#include "scan.h"

//function declarations
int parse_arguments(int argc, char **argv);
int parse_scantype(char *arg, enum scan_type *type);
int parse_target(char *arg, struct target **ret);
struct target buildTarget(char *target_op);
