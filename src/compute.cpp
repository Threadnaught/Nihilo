#include <queue>
#include <vector>
#include <cstring>

#include "../include/platform.h"

thread::locker<std::queue<task*>> task_queue;
thread::locker<std::vector<machine>> local_machines;

void compute::init(int thread_count){
	//TODO: LOAD MACHINES FROM DISK INTO local_machines
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
	memcpy(t->origin_pub, origin_pub, ecc_pub_size);
	//is target machine on this host?
	if(strstr(dest_addr, "~") != nullptr || strstr(dest_addr, "@") != nullptr)//if address contains
	{
		talk::add_to_comm_queue(t);
		return true;
	}
	task_queue.acquire()->push(t);
	task_queue.release();
	return true;
}

bool compute::get_pub(unsigned char* id, unsigned char* pub_out){
	return false;
}
bool compute::get_priv(unsigned char* pub, unsigned char* priv_out){
	auto m = local_machines.acquire();
	
	//this O(N) comparison brings pain to my soul and shame to my descendents
	for(auto it = m->begin(); it != m->end(); it++){
		if(memcmp(it->keypair.ecc_pub, pub, ecc_pub_size) == 0){
			memcpy(priv_out, it->keypair.ecc_priv, ecc_priv_size);
			local_machines.release();
			return true;
		}
	}
	local_machines.release();
	return false;
}
void compute::new_machine(unsigned char* pub_out){
	unsigned char priv[ecc_priv_size];
	crypto::gen_ecdh_keypair(pub_out, priv);
	machine m;
	memcpy(m.keypair.ecc_pub, pub_out, ecc_pub_size);
	memcpy(m.keypair.ecc_priv, priv, ecc_priv_size);
	crypto::id_from_pub(pub_out, m.ID);
	local_machines.acquire()->push_back(m);
	local_machines.release();
	//TODO: ADD TO DB
}