#include <ctype.h> /*  isprint() */
#include <unistd.h> /* getopt() and friends: optarg, optopt, optind */
#include "scan.h"
/* Copyright (c) 2012, Bill Smartt
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of this program nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
 
#define MAX_PORTS 1000
#define VALID_PORT_CEILING 65535
#define VALID_PORT_FLOOR 0

 
//function declarations
struct scan *parse_arguments(int argc, char **argv);
int parse_scantype(char *arg, enum scan_type *type);
int parse_ports(char *ports, unsigned short **list);
int parse_target(char *arg, struct target **ret);
struct target buildTarget(char *target_op);
int split_target_list(char *arg, char **ret);
int count_list_items(char *arg);
char **parse_list(char *arg);
int find_wildcard(char *arg);
int find_wc_position(char *arg);
int find_wc_quad(char *arg);
char **build_targets_from_wc(char *arg, int pre_wc_chars, int *generated);
