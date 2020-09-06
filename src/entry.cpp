#include <iostream>
#include <cstring>

#include "../include/platform.h"

int main(int argc, char** argv){
	recall::init(argv[1]);
	compute::init(1);
	if(argc == 4){
		std::cerr<<"pinging "<<argv[3]<<" from "<<argv[2]<<"\n";
		hex_to_bytes_array(from, argv[2], ecc_pub_size);
		compute::copy_to_queue(argv[3], from, "test", "test", "test", nullptr, 0);
		//compute::copy_to_queue(argv[3], from, "test", nullptr, nullptr, nullptr, 0);
		talk::init(tcp_port);
	}
	else{
		talk::init(tcp_port);
	}
}