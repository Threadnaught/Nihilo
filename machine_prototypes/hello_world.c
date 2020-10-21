#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../include/api.h"

void entry(char* arg){
	uint32_t len;
	char* place = read_DB("place", &len);
	printf("Hello, %s!\n", place);
}