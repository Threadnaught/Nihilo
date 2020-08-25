#pragma once

#include <iostream>
#include <mutex>
#include <errno.h>

#define fail_check(condition, bad_ret) if(!condition) {std::cerr<<"error "<<errno<<": "<<__func__<<"() line "<<__LINE__<<"\n"; return bad_ret;}
#define fail_false(condition) fail_check(condition, false)

#define ID_size 12 //bytes
#define ecc_pub_size 32
#define ecc_priv_size 32
#define shared_secret_size 16
#define aes_block_size 16
#define tcp_port 7328
#define max_func_size 30
#define con_timeout 30
#define max_packet_size 512
#define max_func_len 20

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
	unsigned char dest_pub[ecc_pub_size];
	int retry_count = 3;
	char* ret = nullptr;
	wire_task t;
};

namespace crypto{
	int calc_encrypted_size(int bodylen);
}

namespace thread{
	template <typename T> class locker{
		public:
			locker(T wraps);
			T* acquire();
			void release();
		private:
			T contains;
			std::mutex mutex;
	};
}

namespace compute{
	void init(int thread_count);
}

namespace talk{
	void init(int port);
}