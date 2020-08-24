#include "../include/platform.h"
namespace crypt{
	int calc_encrypted_size(int bodylen){//Round up to the nearest block size, and add one block
		int blockno = (bodylen + aes_block_size - 1) / aes_block_size;
		return (blockno + 1) * aes_block_size;
	}
}

namespace thread{
	//locker functions:
	template <typename T> 
	locker<T>::locker(T wraps){
		contains = wraps;
	}
	template <typename T> 
	T* locker<T>::acquire(){
		mutex.lock();
		return &contains;
	}
	template <typename T> 
	void locker<T>::release(){
		mutex.unlock();
	}
}