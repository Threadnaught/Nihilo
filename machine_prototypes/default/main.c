#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/api.h"

void entry(char* arg){
	queue("nihilo_host~195734F260E4E4782B432F9A71A6EB69EA4EE821D9D72FDC4C68F227F3D54D1C", "test", NULL, NULL, NULL, 0);
}
void test(char* arg){
	printf("hello, there!\n");
}