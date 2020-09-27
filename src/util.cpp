#include "../include/platform.h"
#include <cstring>

int crypto::calc_encrypted_size(int bodylen){//Round up to the nearest block size, and add one block
	int blockno = (bodylen + aes_block_size - 1) / aes_block_size;
	return (blockno + 1) * aes_block_size;
}

void bytes_to_hex(unsigned char* bytes, int bytes_len, char* hexbuffer){
	for(int i = 0; i < bytes_len; i++)
		snprintf(hexbuffer + (i*2), 3, "%02X", bytes[i]);
}
void hex_to_bytes(char* hexbuffer, unsigned char* bytes){
	for(int i = 0; i < strlen(hexbuffer)/2; i++){
		unsigned int val;
		sscanf(hexbuffer + (i*2), "%02X", &val);
		bytes[i] = (unsigned char)val;
	}
}