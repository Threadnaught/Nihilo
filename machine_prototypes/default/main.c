#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/api.h"

void entry(char* arg){
	//queue("pinger~214D970D557E0A205F1592C5A90568335D88E4312CADD3F9EB6A38B1D3A4CAEB", "inner", "inner_sucesss", "inner_failure", NULL, 0);
	//const char* bloop = "bloop";
	//write_DB("test.test", bloop, strlen(bloop)+1);
	uint32_t read_length;
	char* read = (char*)read_DB("test.yes", &read_length);
	printf("read out again: %s\n", read);
}
void inner(char* arg){
	printf("inner\n");
	//set_return(1, NULL, 0);
}
void inner_sucesss(char* arg){
	printf("success\n");
}
void inner_failure(char* arg){
	printf("failure\n");
}
