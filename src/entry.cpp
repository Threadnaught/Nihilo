#include <iostream>
#include <cstring>
#include <unistd.h>

#include "../include/platform.h"

int main(int argc, char** argv){
	char db_path[100];
	char ping_addr[100];
	char ping_from[100];
	strncpy(db_path, "/tmp/testdb", 99);
	memset(ping_addr, 0, sizeof(ping_addr));
	memset(ping_from, 0, sizeof(ping_from));
	int opt;
	fail_check(recall::init(db_path), -1);
	fail_check(compute::init(), -1);
	bool entry = false;
	while((opt = getopt(argc, argv, "d:m:p:f:e")) != -1){//-d database path -w wasm path -p ping address
		switch(opt){
			case 'd':
				strncpy(db_path, optarg, 99);
				break;
			case 'm':
				fail_check(compute::load_from_proto_file(optarg),-1);
				break;
			case 'p':
				strncpy(ping_addr, optarg, 99);
				break;
			case 'f':
				strncpy(ping_from, optarg, 99);
				break;
			case 'e':
				entry = true;
				break;
			default:
				std::cerr<<"unrecognised argument\n";
				return 1;
		}
	}

	unsigned char root_pub[ecc_pub_size];
	char root_hex[(ecc_pub_size*2)+1];
	compute::get_default_machine(root_pub);
	bytes_to_hex(root_pub, ecc_pub_size, root_hex);
	if(entry){
		strcpy(ping_addr, root_hex);
	}
	if(strlen(ping_addr) > 0){
		if(strlen(ping_from) == 0){
			strcpy(ping_from, root_hex);
		}
		std::cerr<<"pinging "<<ping_addr<<" from "<<ping_from<<"\n";
		const char* param = "hello, world!";
		compute::copy_to_queue(ping_addr, ping_from, "entry", nullptr, nullptr, param, strlen(param)+1);
	}
	fail_check(runtime::init(), -1);
	fail_check(compute::launch_threads(1), -1);
	talk::init(tcp_port);
}