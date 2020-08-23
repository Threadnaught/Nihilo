#include "../include/platform.h"
namespace crypt{
	int calc_encrypted_size(int bodylen){//Round up to the nearest block size, and add one block
		int blockno = (bodylen + aes_block_size - 1) / aes_block_size;
		return (blockno + 1) * aes_block_size;
	}
}