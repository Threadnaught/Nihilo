#include <iostream>
#include <cstring>

#include "../include/platform.h"

int main(){
	/*recall::init("/tmp/testdb");
	unsigned char A_pub[ecc_pub_size];
	unsigned char A_priv[ecc_priv_size];
	unsigned char B_pub[ecc_pub_size];
	unsigned char B_priv[ecc_priv_size];

	crypt::gen_ecdh_keypair(A_pub, A_priv);
	crypt::gen_ecdh_keypair(B_pub, B_priv);

	unsigned char A_secret[shared_secret_size];
	unsigned char B_secret[shared_secret_size];

	crypt::derrive_shared(A_priv, B_pub, A_secret);
	crypt::derrive_shared(B_priv, A_pub, B_secret);

	std::cout<<(memcmp(A_secret, B_secret, shared_secret_size)==0?"matches\n":"no match\n");*/
	talk::init(tcp_port);
}