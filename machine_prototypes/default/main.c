#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/api.h"

void entry(char* arg){
	//const char* test = "patrick";
	//queue("pinger~0FF1E3D571F304E391888F6A9E72BE68588B7B6273A540CBB02F5C52A3EEF99E", "test", "success", "failure", test, strlen(test)+1);
	printf("entry\n");
}
void test(char* arg){
	printf("hello, %s\n", arg);
	set_return(1, "test", 5);
}
void success(char* arg){
	printf("success, %s\n", arg);
}
void failure(char* arg){
	printf("failure, %s\n", arg);
}