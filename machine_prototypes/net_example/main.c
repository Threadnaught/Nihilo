#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/api.h"

//same as com_example, but across a network

/*void TEMP_whatever(const char* arg){
	printf("yeap\n");
}*/
void entry(const char* arg){
	char* server_address = read_DB("server_address", NULL);
	printf("querying place out of %s\n", server_address);
	queue(server_address, "get_place", "success", "failure", NULL, 0);
	free(server_address);
}
void get_place(const char* arg){
	uint32_t ret_len;
	set_return(1, read_DB("place", &ret_len), ret_len);
}
void success(const char* arg){
	printf("Answer from #place_server: %s\n", arg);
}
void failure(const char* arg){
	printf("get_place on #place_server failed\n");
}