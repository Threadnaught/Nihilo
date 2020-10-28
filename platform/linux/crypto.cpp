#include<cstring>
#include<cstdio>
#include<iostream>

#include "mbedtls/aes.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/sha256.h"

#include"../../include/platform.h"

namespace crypto{
	bool encrypt(const unsigned char* secret, const unsigned char* to_encrypt, int to_encrypt_len, unsigned char* encrypted_buf){
		//verify valid size:
		fail_false(to_encrypt_len % aes_block_size == 0);
		mbedtls_aes_context aes;
		//init context, set secret:
		mbedtls_aes_init(&aes);
		fail_false(mbedtls_aes_setkey_enc(&aes, secret, shared_secret_size * 8) == 0);
		//start with initialization vector:
		unsigned char* init_vector_source = encrypted_buf;
		encrypted_buf += aes_block_size;
		rng(nullptr, init_vector_source, aes_block_size);
		//mbedtls_aes_crypt_cbc alters IV buffer
		unsigned char init_vector[aes_block_size];
		memcpy(init_vector, init_vector_source, aes_block_size);
		//encypt data:
		fail_false(mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, to_encrypt_len, init_vector, to_encrypt, encrypted_buf) == 0);
		mbedtls_aes_free(&aes);
		return true;
	}
	
	bool decrypt(const unsigned char* secret, unsigned char* to_decrypt, int to_decrypt_len, unsigned char* decrypted_buf){
		fail_false(to_decrypt_len % aes_block_size == 0);
		mbedtls_aes_context aes;
		mbedtls_aes_init(&aes);
		fail_false(mbedtls_aes_setkey_dec(&aes, secret, shared_secret_size * 8) == 0);
		unsigned char* init_vector = to_decrypt;
		to_decrypt += aes_block_size;
		fail_false(mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, to_decrypt_len, init_vector, to_decrypt, decrypted_buf) == 0);
		mbedtls_aes_free(&aes);
		return true;
	}

	bool gen_ecdh_keypair(unsigned char* pub, unsigned char* priv){
		//create eliptic curve machine
		mbedtls_ecdh_context ecc;
		//init ecdh/curves:
		mbedtls_ecdh_init(&ecc);
		fail_false(mbedtls_ecp_group_load(&ecc.grp, MBEDTLS_ECP_DP_CURVE25519) == 0);
		//create public:
		fail_false(mbedtls_ecdh_gen_public(&ecc.grp, &ecc.d, &ecc.Q, rng, NULL) == 0);
		//dump keys:
		fail_false(mbedtls_mpi_write_binary(&ecc.Q.X, pub, ecc_pub_size) == 0);
		fail_false(mbedtls_mpi_write_binary(&ecc.d, priv, ecc_priv_size) == 0);
		mbedtls_ecdh_free(&ecc);
		return true;
	}

	bool derrive_shared(const unsigned char* alice_priv, const unsigned char* bob_pub, unsigned char* secret_buf){
		mbedtls_ecdh_context ecc;
		mbedtls_ecdh_init(&ecc);
		fail_false(mbedtls_ecp_group_load(&ecc.grp, MBEDTLS_ECP_DP_CURVE25519) == 0);
		//write pub:
		fail_false(mbedtls_mpi_lset(&ecc.Qp.Z, 1) == 0);
		fail_false(mbedtls_mpi_read_binary(&ecc.Qp.X, bob_pub, ecc_pub_size) == 0);
		//write priv:
		fail_false(mbedtls_mpi_read_binary(&ecc.d, alice_priv, ecc_priv_size) == 0);
		//create secret:
		fail_false(mbedtls_ecdh_compute_shared(&ecc.grp, &ecc.z, &ecc.Qp, &ecc.d, rng, NULL) == 0);
		int shared_size = mbedtls_mpi_size(&ecc.z);
		fail_false(shared_size >= shared_secret_size);
		//write into secret_buf
		unsigned char* intermediate_secret_buf = new unsigned char[shared_size];
		fail_false(mbedtls_mpi_write_binary(&ecc.z, intermediate_secret_buf, shared_size) == 0);
		memcpy(secret_buf, intermediate_secret_buf, shared_secret_size);
		delete intermediate_secret_buf;
		//cleanup
		mbedtls_ecdh_free(&ecc);
		return true;
	}
	
	int rng(void* state, unsigned char* outbytes, size_t len){
		FILE* rand = fopen("/dev/urandom", "rb");//TODO: eval if urandom is good?
		fread(outbytes, 1, len, rand);
		return 0;
	}
}