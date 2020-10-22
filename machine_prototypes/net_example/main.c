#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/api.h"

/*This file demonstrates the basic nihilo communication flow;
	1. machines #root and #place_server are loaded.
	2. The nihilo host executes entry() on #root. This queues a call to get_place on #place_server.
	3. The nihilo host executes get_place() on #place_server. This reads the place value from the DB, and returns it to #root.
	4.	I.	If get_place() executes sucessfully, success() will be queued on #root, and it will print out the returned place.
		II.	If get_place() fails, failure() will be queued on #root, and it will print an error.
*/

void entry(const char* arg){
	uint32_t ret_len;
	char* server_address = read_DB("server_address", &ret_len);
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