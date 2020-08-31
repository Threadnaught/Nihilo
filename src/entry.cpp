#include <iostream>
#include <cstring>

#include "../include/platform.h"

int main(int argc, char** argv){
	std::cerr<<"running\n";
	if(argc == 2){
		std::cerr<<"pinging "<<argv[1]<<"\n";
		unsigned char dummy[ecc_pub_size];
		crypto::rng(nullptr, dummy, ecc_pub_size);
		compute::copy_to_queue(argv[1], dummy, "test", nullptr, nullptr, nullptr, 0);
		talk::init(tcp_port);
	}
	else{
		talk::init(tcp_port);
	}
}