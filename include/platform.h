#pragma once

#include<cstdio>
#include<map>

#include "nih.h"

namespace recall{
	bool init(const char* dbpath);//dbpath can be empty string if not relevant for platform
	bool write(const char* key, const void* data, int datalen);//write key/value pair into db
	void* read(const char* key, int* datalen);//read kvp from db
	//char* next(const char* prev_key);//find next key after given key
	bool delete_all_with_prefix(const char* prefix);
	void acquire_lock();//recall requires more fine-grained locking control than other things
	void release_lock();
}

namespace crypto{
	//AES functions:
	bool encrypt(const unsigned char* secret, const unsigned char* to_encrypt, int to_encrypt_len, unsigned char* encrypted_buf);
	bool decrypt(const unsigned char* secret, unsigned char* to_decrypt, int to_decrypt_len, unsigned char* decrypted_buf);
	//ECDH functions:
	bool gen_ecdh_keypair(unsigned char* pub, unsigned char* priv);
	bool derrive_shared(const unsigned char* alice_priv, const unsigned char* bob_pub, unsigned char* secret_buf);
	//misc functions:
	int rng(void* state, unsigned char* outbytes, size_t len); //MUST BE CRYPTOGRAPHICALLY SECURE
	bool id_from_pub(const unsigned char* pub, unsigned char* id);
}

namespace runtime{
	bool init();
	bool exec_task(host_task* t);
}

namespace intercepts{
	struct intercept_param{
		uint16_t length;
		void* ret;
	};
	typedef intercept_param (*raw_intercept_func)(intercept_param);
	struct intercept_func{
		const char* name;
		raw_intercept_func func;
		//TODO: machine type (root etc.)
	};
	void register_intercepts(std::map<std::string, intercept_func>& map);
}