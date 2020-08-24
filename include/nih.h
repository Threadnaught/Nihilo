#pragma once

#include <iostream>
#include <mutex>

#define fail_check(condition, bad_ret) if(!condition) {std::cerr<<"bad fail check: "<<__func__<<"() at line "<<__LINE__<<"\n"; return bad_ret;}
#define fail_false(condition) fail_check(condition, false)

#define ID_size 12 //bytes
#define ecc_pub_size 32
#define ecc_priv_size 32
#define shared_secret_size 16
#define aes_block_size 16
#define tcp_port 7328
#define max_func_size 30

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

struct wire_task{};
struct task{};

namespace crypt{
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