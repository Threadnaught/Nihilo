#pragma once

#include <iostream>
#include <mutex>
#include <errno.h>

#define fail_check(condition, bad_ret) if(!condition) {std::cerr<<"error "<<errno<<": "<<__func__<<"() line "<<__LINE__<<"\n"; return bad_ret;}
#define fail_false(condition) fail_check(condition, false)

//size in bytes len in chars

#define ID_size 12
#define ecc_pub_size 32
#define ecc_priv_size 32
#define shared_secret_size 16
#define aes_block_size 16
#define tcp_port 7328
#define con_timeout 30
#define max_packet_size 512
#define max_func_len 20
#define max_address_len 100

struct machine_keypair{
	unsigned char ecc_pub[ecc_pub_size];
	unsigned char ecc_priv[ecc_priv_size];
};

struct machine{
	unsigned char ID[ID_size];
	char ID_str[(ID_size*2)+1];
	machine_keypair keypair;
	bool local;
	char IP[20];
};

struct packet_header{
	unsigned char origin_pub[ecc_pub_size];
	unsigned char dest_pub[ecc_pub_size];
	uint16_t contents_length; //packet true length = (roundup(contents_length/aes_block_size)+1)*aes_block_size
};

//both types of task are followed by the param (of variable length)

struct wire_task{ //task on the wire
	char function_name[max_func_len];
	char on_success[max_func_len];
	char on_failure[max_func_len];
};
struct task{//task (full)
	unsigned char origin_pub[ecc_pub_size];
	char dest_addr[max_address_len];
	int retry_count = 3;
	char* ret = nullptr;
	short param_length; //0 for no param
	wire_task t;
};

namespace crypto{
	int calc_encrypted_size(int bodylen);
}

namespace thread{
	//no one hates code in headers more than me, but I literally cannot get this shit working any other way
	template <typename T> class locker{
		public:
			T* acquire(){
				mutex.lock();
				return &contains;
			}
			void release(){
				mutex.unlock();
			}
		private:
			T contains;
			std::mutex mutex;
	};
}

namespace compute{
	void init(int thread_count);
	bool copy_to_queue(const char* dest_addr, const unsigned char* origin_pub, const char* function_name, const char* on_success, const char* on_failure, const unsigned char* param, int paramlen);
}

namespace talk{
	void init(int port);
	void copy_to_comm_queue(task* t);
}