#include <ctype.h> /*  isprint() */
#include <unistd.h> /* getopt() and friends: optarg, optopt, optind */

#include "scan.h"
//function declarations
struct scan *parse_arguments(int argc, char **argv);
int parse_scantype(char *arg, enum scan_type *type);
int parse_target(char *arg, struct target **ret);
struct target buildTarget(char *target_op);
int split_target_list(char *arg, char **ret);
int count_list_items(char *arg);
char **parse_list(char *arg);
int find_wildcard(char *arg);
int find_wc_position(char *arg);
int find_wc_quad(char *arg);
char **build_targets_from_wc(char *arg, int pre_wc_chars, int *generated);
