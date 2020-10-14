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
	bool encrypt(const key_byte* secret, const unsigned char* to_encrypt, int to_encrypt_len, unsigned char* encrypted_buf);
	bool decrypt(const key_byte* secret, unsigned char* to_decrypt, int to_decrypt_len, unsigned char* decrypted_buf);
	//ECDH functions:
	bool gen_ecdh_keypair(key_byte* pub, key_byte* priv);
	bool derrive_shared(const key_byte* alice_priv, const key_byte* bob_pub, key_byte* secret_buf);
	//misc functions:
	int rng(void* state, unsigned char* outbytes, size_t len); //MUST BE CRYPTOGRAPHICALLY SECURE
	bool id_from_pub(const key_byte* pub, key_byte* id);
}

namespace runtime{
	bool init();
	bool exec_task(host_task* t);
}
//Currently only supports root
namespace intercepts{
	struct intercept_param{
		uint16_t length;
		void* ret;
	};
	typedef intercept_param (*raw_intercept_func)(intercept_param);
	struct intercept_func{
		const char* name;
		raw_intercept_func func;
	};
	void register_intercepts(std::map<std::string, intercept_func>& map);
}