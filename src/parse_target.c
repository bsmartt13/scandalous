#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "parse_target.h"

/*******************************************************************************
 *  File: parse_target.c
 *  Author: Bill Smartt <bsmartt13@gmail.com>
 *  Description: Helper functions to the main command line argument parser.
 *		This file deals with building a list of the valid IPs in a string like
 *		"192.168.1.101-110,192.168.2.*,192.168.*.250-254".  
 *  Status: Implemented.  
 *			Tested (Ubuntu 11.10 32-bit, Backtrack 5r1 32-bit gnome).  
 *			Working (afaik).  
 *  Please contact me if it is not working for you.
 ******************************************************************************/

/*  int split_target_list(char *arg, char **ret):
 *  Splits list at the seperator ",".  returns an array of the IP address in the
 *  function arg char **ret.  returns the number of targets found.
 */
int split_target_list(char *arg, char **ret){

	int count = count_list_items(arg);
	printf("count is: %d (list_targets)\n",count);
	printf("arg is %s\n", arg);
	
	const char list_delim[] = ",";
	char *token;
	char *running;
	int targs_found = 0;
	
	running = strdup(arg); //must not free this memory until target ip is saved to struct target.
	token = strsep(&running, list_delim);
	ret[targs_found] = (char *) malloc (sizeof (char) * strlen(token));
	ret[targs_found++] = token;
#ifdef DEBUG
	printf("new target found: %s\n", ret[targs_found - 1]);
#endif
	for(; targs_found < count && token != NULL; targs_found++){
		token = strsep(&running, list_delim);
		ret[targs_found] = (char *) malloc (sizeof (char) * strlen(token));
		ret[targs_found] = token;
	#ifdef DEBUG
		printf("new target found: %s\n", ret[targs_found]);
	#endif
	}
	return targs_found;
}

/*  int count_list_items(char *arg):
 *  counts the number of items in a list seperated by ",".
 */
int count_list_items(char *arg){
	int count = 1, index = 0;
	while (arg[index] != '\0'){
		if (arg[index++] == ',')
			count++;
	}
	return count;
}

/*  char **parse_list(char *arg):
 *  ensures the list is properly parsed.
 */
char **parse_list(char *arg){
	int counted = 0, found = 0;
	char **parsed;
	counted = count_list_items(arg);
	parsed = (char **) malloc (sizeof (char *) * counted);
	found = split_target_list(arg, parsed);
	return parsed;
}
/*
int main (int argc, char **argv){

	int i = 0, ct = 0;
	char **target_list;
	ct = count_list_items(argv[1]);
	target_list = parse_list(argv[1]);	
	for (i = 0; i < ct; i++) {
		printf("target found: %s\n", target_list[i]);
	}
	return 0;
}
*/
