#include <stdio.h>
#include <string.h>
#include <stdlib.h>


int split_target_list(char *arg, char **ret);
int count_list_items(char *arg);
char **parse_list(char *arg);
int find_wildcard(char *arg);
int find_wc_position(char *arg);
int find_wc_quad(char *arg);
char **build_targets_from_wc(char *arg, int pre_wc_chars);
