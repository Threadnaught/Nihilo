#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../include/api.h"

void entry(char* arg){
	queue("pinger~64453268BD298278F295067C5881C325BBE315D2DCF20894E13822509AF95708", "inner", "inner_sucesss", "inner_failure", NULL, 0);
}
void inner(char* arg){
	printf("hi\n");
	//set_return(0, NULL, 0);
}
void inner_sucesss(char* arg){
	printf("success\n");
}
void inner_failure(char* arg){
	printf("failure\n");
}
