#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/api.h"

void entry(const char* arg){
	queue_str("#root", "http_register", NULL, "failure", "handler");
}
void handler(const char* arg){
	char* ret_str = read_DB("page", NULL);
	char* whole_ret = malloc(strlen(ret_str)+34);
	memcpy(whole_ret, arg, 32);
	whole_ret[32] = '/';
	memcpy(whole_ret+33, ret_str, strlen(ret_str)+1);
	//printf("replying %s \n", whole_ret);
	set_return(1, whole_ret, strlen(whole_ret)+1);
}
void update_page(const char* arg){
	write_DB("page", arg, strlen(arg)+1);
}
void failure(const char* arg){
	printf("failure\n");
}
