#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/api.h"

void entry(const char* arg){
	char* place = read_DB("place", NULL);
	printf("Hello, %s!\n", place);
	free(place);//not strictly required but good practise
}