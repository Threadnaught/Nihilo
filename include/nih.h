#pragma once

#include <iostream>
#include <mutex>
#include <errno.h>

//size in bytes len in chars

#define ID_size 12
#define ecc_pub_size 32
#define ecc_priv_size 32
#define shared_secret_size 16
#define aes_block_size 16
#define tcp_port 7328
#define con_timeout 15
#define max_packet_size 512
#define max_func_len 20
#define max_address_len 100

struct machine_keypair{
	unsigned char ecc_pub[ecc_pub_size];
	unsigned char ecc_priv[ecc_priv_size];
};

struct machine{
	unsigned char ID[ID_size];
	machine_keypair keypair;
};

struct packet_header{
	unsigned char origin_pub[ecc_pub_size];
	unsigned char dest_pub[ecc_pub_size];
	uint16_t contents_length; //packet true length = (roundup(contents_length/aes_block_size)+1)*aes_block_size
};

//both types of task are followed by the param (of variable length)

struct common_task{ //task on the wire
	char function_name[max_func_len];
	char on_success[max_func_len];
	char on_failure[max_func_len];
};
struct host_task{//task (full)
	unsigned char origin_pub[ecc_pub_size];
	char dest_addr[max_address_len];
	int retry_count = 3;
	char* ret = nullptr;
	short param_length; //0 for no param
	common_task t;
};
//THIS NEEDS TO STAY IN THIS EXACT ORDER OR send_comm WILL ALL GET FUCKED
struct wire_task{
	unsigned char target_ID[ID_size];
	common_task t;
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
	bool init();
	void launch_threads(int thread_count);
	bool copy_to_queue(const char* dest_addr, const unsigned char* origin_pub, const char* function_name, const char* on_success, const char* on_failure, const unsigned char* param, int paramlen);
	bool get_pub(unsigned char* id, unsigned char* pub_out);
	bool get_priv(unsigned char* pub, unsigned char* priv_out);
	void new_machine(unsigned char* pub_out);
	bool save_wasm(unsigned char* pub, unsigned char* wasm, int length);
	unsigned char* get_wasm(unsigned char* pub, int* length);
	//TEMP/DEBUG:
	void get_default_machine(unsigned char* pub_out);
}

namespace talk{
	void init(int port);
	void add_to_comm_queue(host_task* t);
}

void bytes_to_hex(unsigned char* bytes, int bytes_len, char* hexbuffer);
void hex_to_bytes(char* hexbuffer, unsigned char* bytes);

#define fail_check(condition, bad_ret) if(!(condition)) {std::cerr<<"error "<<errno<<": "<<__func__<<"() line "<<__LINE__<<"\n"; return bad_ret;}
#define fail_false(condition) fail_check(condition, false)
#define bytes_to_hex_array(name, bytes, len) char name[(len*2)+1]; bytes_to_hex(bytes, len, name);
#define hex_to_bytes_array(name, str, len) unsigned char name[len]; hex_to_bytes(str, name);