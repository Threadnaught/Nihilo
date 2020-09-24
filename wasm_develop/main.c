#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../include/api.h"

void calculate(char* arg){
	if(arg != NULL)
		printf("str:%s\n", arg);
	else
		printf("null\n");
}