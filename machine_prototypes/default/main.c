#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/api.h"

void entry(char* arg){
	//const char* test = "patrick";
	queue("#test", "test", NULL, NULL, NULL, 0);
	printf("entry\n");
}
void test(char* arg){
	printf("this is a test\n");
}