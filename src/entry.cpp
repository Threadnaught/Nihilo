#include <iostream>
#include <cstring>
#include <unistd.h>

#include "../include/platform.h"

int main(int argc, char** argv){
	char db_path[100];
	char ping_to[100];
	char ping_from[100];
	int port = tcp_port;
	strncpy(db_path, "/tmp/testdb", 99);
	memset(ping_to, 0, sizeof(ping_to));
	memset(ping_from, 0, sizeof(ping_from));
	int opt;
	fail_check(recall::init(db_path), -1);
	fail_check(compute::init(), -1);
	bool entry = false;
	while((opt = getopt(argc, argv, "d:m:t:f:e:p:")) != -1){//-d database path -m machine path -t ping to -f ping from -e run entry on this host's root
		switch(opt){
			case 'd':
				strncpy(db_path, optarg, 99);
				break;
			case 'm':
				fail_check(compute::load_from_proto_file(optarg),-1);
				break;
			case 't':
				strncpy(ping_to, optarg, 99);
				break;
			case 'f':
				strncpy(ping_from, optarg, 99);
				break;
			case 'e':
				entry = true;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			default:
				std::cerr<<"unrecognised argument\n";
				return 1;
		}
	}
	unsigned char root_pub[ecc_pub_size];
	if(entry){
		strcpy(ping_to, "#root");
	}
	if(strlen(ping_to) > 0){
		if(strlen(ping_from) == 0){
			strcpy(ping_from, "#root");
		}
		std::cerr<<"pinging "<<ping_to<<" from "<<ping_from<<"\n";
		compute::copy_to_queue(ping_to, ping_from, "entry", nullptr, nullptr, nullptr, 0);
	}
	fail_check(runtime::init(), -1);
	fail_check(compute::launch_threads(1), -1);
	talk::init(port);
}