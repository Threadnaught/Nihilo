#include <queue>
#include <cstring>

#include "../include/platform.h"

thread::locker<std::queue<task*>> task_queue;

void compute::init(int thread_count){

}

void run_compute_worker(){
	while(1){
		//remove task from queue
		//load wasm
		//execute wasm (using platform exec)
	}
}

bool compute::copy_to_queue(const char* dest_addr, const unsigned char* origin_pub, const char* function_name, const char* on_success, const char* on_failure, const unsigned char* param, int paramlen){
	//ensure compliance:
	fail_false(!(strlen(dest_addr) > max_address_len));
	fail_false(!(strlen(function_name) > max_func_len));
	if(on_success != nullptr) fail_false(!(strlen(on_success) > max_func_len));
	if(on_failure != nullptr) fail_false(!(strlen(on_failure) > max_func_len));
	fail_false(!(paramlen > max_packet_size));//this probably needs some tuning
	//construt task
	task* t = (task*)malloc(sizeof(task) + paramlen);
	strncpy(t->dest_addr, dest_addr, max_address_len);
	strncpy(t->t.function_name, function_name, max_func_len);
	if(on_success != nullptr) strncpy(t->t.on_success, function_name, max_func_len);
	if(on_failure != nullptr) strncpy(t->t.on_failure, function_name, max_func_len);
	if(paramlen > 1) memcpy((t+1), param, paramlen);
	//is target machine on this host?
	if(strstr(dest_addr, "~") != nullptr || strstr(dest_addr, "@") != nullptr)//if address contains
	{
		talk::copy_to_comm_queue(t);
		return true;
	}
	task_queue.acquire()->push(t);
	task_queue.release();
	return true;
}