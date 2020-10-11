#include <iostream>
#include <cstring>
#include <unistd.h>

#include "../include/platform.h"

int main(int argc, char** argv){
	char db_path[100];
	char proto_path[100];
	char ping_addr[100];
	char ping_from[100];
	strncpy(db_path, "/tmp/testdb", 99);
	memset(proto_path, 0, 100);
	memset(ping_addr, 0, 100);
	memset(ping_from, 0, 100);
	int opt;
	while((opt = getopt(argc, argv, "d:m:p:f:")) != -1){//-d database path -w wasm path -p ping address
		switch(opt){
			case 'd':
				strncpy(db_path, optarg, 99);
				break;
			case 'm':
				strncpy(proto_path, optarg, 99);
				break;
			case 'p':
				strncpy(ping_addr, optarg, 99);
				break;
			case 'f':
				strncpy(ping_from, optarg, 99);
				break;
			default:
				std::cerr<<"unrecognised argument\n";
				return 1;
		}
	}
	fail_check(recall::init(db_path), -1);
	fail_check(compute::init(), -1);
	if(strlen(proto_path) > 0)
		compute::load_from_proto(proto_path);
	
	if(strlen(ping_addr) > 0 && strlen(ping_from) > 0){
		std::cerr<<"pinging "<<ping_addr<<" from "<<ping_from<<"\n";
		const char* param = "hello, world!";
		compute::copy_to_queue(ping_addr, ping_from, "entry", nullptr, nullptr, param, strlen(param)+1);
	}
	fail_check(runtime::init(), -1);
	fail_check(compute::launch_threads(1), -1);
	talk::init(tcp_port);
}