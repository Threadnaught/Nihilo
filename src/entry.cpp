#include <iostream>
#include <cstring>
#include <unistd.h>

#include "../include/platform.h"

int main(int argc, char** argv){
	char db_path[100];
	char wasm_path[100];
	char ping_addr[100];
	char ping_from[100];
	strncpy(db_path, "/tmp/testdb", 99);
	memset(wasm_path, 0, 100);
	memset(ping_addr, 0, 100);
	memset(ping_from, 0, 100);
	int opt;
	while((opt = getopt(argc, argv, "d:w:p:f:")) != -1){//-d database path -w wasm path -p ping address
		switch(opt){
			case 'd':
				strncpy(db_path, optarg, 99);
				break;
			case 'w':
				strncpy(wasm_path, optarg, 99);
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
	if(strlen(wasm_path) > 0){
		FILE* wasm_file = fopen(wasm_path, "rb");
		fseek(wasm_file, 0, SEEK_END);
		int length = ftell(wasm_file);
		fseek(wasm_file, 0, SEEK_SET);
		unsigned char* wasm_data = new unsigned char[length];
		fread(wasm_data, length, 1, wasm_file);
		fclose(wasm_file);
		unsigned char default_mach[ecc_pub_size];
		compute::get_default_machine(default_mach);
		compute::save_wasm(default_mach, wasm_data, length);
		delete wasm_data;
	}
	if(strlen(ping_addr) > 0 && strlen(ping_from) > 0){
		std::cerr<<"pinging "<<ping_addr<<" from "<<ping_from<<"\n";
		//hex_to_bytes_array(from, ping_from, ecc_pub_size);
		compute::copy_to_queue(ping_addr, ping_from, "calculate", "calculate", nullptr, nullptr, 0);
	}
	fail_check(runtime::init(), -1);
	fail_check(compute::launch_threads(1), -1);
	talk::init(tcp_port);
}