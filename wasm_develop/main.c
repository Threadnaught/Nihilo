#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../include/api.h"

void calculate(char* arg){
	unsigned char test[50];
	strcpy((char*)test, "right back at ye");
	set_return(1, test, 50);
	
	if(arg != NULL)
		printf("str:%s\n", arg);
	else
		printf("null\n");
}