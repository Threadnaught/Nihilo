#include <queue>
#include <vector>
#include <cstring>
#include <pthread.h>
#include <unistd.h>

#include "../include/platform.h"

thread::locker<std::queue<host_task*>> task_queue;
thread::locker<std::map<compute::pub_key, machine>> local_machines;
std::map<std::string, compute::pub_key> local_name_index; //shares local_machines locker (TODO: create struct to lock both in the same locker)
std::map<std::string, intercepts::intercept_func> platform_intercepts;

bool compute::operator< (const pub_key k1, const pub_key k2){
	return memcmp(k1.key, k2.key, ecc_pub_size) < 0;
}
compute::pub_key compute::pub_conv(unsigned char* p){
	return *(compute::pub_key*)p;
}

void delete_task(host_task* t){
	if(t->ret_len > 0){
		free(t->ret);
	}
	delete t;
}

bool compute::init(){
	//load machines into local_machines:
	int table_len;
	unsigned char* table = (unsigned char*)recall::read("machines_table", &table_len);
	//if the table cannot be found, recreate db
	if(table == nullptr){
		std::cerr<<"recreating DB\n";
		unsigned char c;
		recall::write("machines_table", &c, 0);
		unsigned char new_pub[ecc_pub_size];
		fail_false(new_machine("root", new_pub));
		table = (unsigned char*)recall::read("machines_table", &table_len);
	}
	//std::cerr<<"table size: "<<table_len<<"\n";
	fail_false(table_len % ecc_pub_size == 0);
	auto locals = local_machines.acquire();
	for(int i = 0; i < table_len; i += ecc_pub_size){
		int m_len;
		bytes_to_hex_array(pub_hex, table + i, ecc_pub_size);
		std::cerr<<"loading machine "<<pub_hex<<"\n";
		machine* m = (machine*)recall::read(pub_hex, &m_len);
		fail_false(m_len == sizeof(machine));
		(*locals)[pub_conv(table+i)] = *m;
		local_name_index[m->name] = pub_conv(m->keypair.ecc_pub);
	}
	local_machines.release();
	delete table;
	intercepts::register_intercepts(platform_intercepts);
	//std::cerr<<"intercepts:"<<platform_intercepts.size()<<"\n";
	return true;
}
bool handle_individual_task(host_task* t){
	unsigned char dest_pub[ecc_pub_size];
	fail_false(compute::resolve_local_machine(t->dest_addr, dest_pub));
	//check if this call is intercepted
	auto found = platform_intercepts.find(t->t.function_name);
	unsigned char root[ecc_pub_size];
	compute::get_root_machine(root);
	if(memcmp(root, dest_pub, ecc_pub_size) == 0 && found != platform_intercepts.end()){//check for intercepts
		(*(found->second.func))(t);
		return true;
	} else 
		return runtime::exec_task(t);
}
//loops checking for a task at the front of the queue, and exec
void* run_compute_worker(void* args){
	while(1){
		//std::cerr<<"loop\n";
		auto acquired_queue = task_queue.acquire();
		host_task* t = nullptr;
		if(acquired_queue->size() > 0){
			t = acquired_queue->front();
			acquired_queue->pop();
		}
		task_queue.release();
		if(t!=nullptr){
			bool success = handle_individual_task(t);
			const char* call_now = success && t->success?t->t.on_success:t->t.on_failure;
			if(strlen(call_now) > 0){
				void* param = t->ret_len>0?t->ret:nullptr;
				compute::copy_to_queue(t->origin_addr, t->dest_addr, call_now, nullptr, nullptr, t->ret, t->ret_len);
			}
			delete_task(t);
		}
		else
			usleep(1000);
	}
}

bool compute::launch_threads(int thread_count){
	for(int i = 0; i < thread_count; i++){
		pthread_t thread;
		fail_false(pthread_create(&thread, nullptr, run_compute_worker, nullptr)==0);
	}
	return true;
}

bool compute::copy_to_queue(const char* dest_addr, const char* origin_addr, const char* function_name, const char* on_success, const char* on_failure, const void* param, int paramlen){
	//std::cerr<<"Sending "<<function_name<<" to "<<dest_addr<<"\n";
	//ensure compliance:
	fail_false(!(strlen(dest_addr) > max_address_len));
	fail_false(!(strlen(function_name) > max_func_len));
	if(on_success == nullptr) on_success = "";
	if(on_failure == nullptr) on_failure = "";
	fail_false(!(strlen(on_success) > max_func_len));
	fail_false(!(strlen(on_failure) > max_func_len));
	fail_false(!(paramlen > max_packet_size));//this probably needs some tuning
	//construct task
	host_task* t = (host_task*)malloc(sizeof(host_task) + paramlen);
	memset(t, 0, sizeof(host_task));//don't want to expose any memory now, do we?
	strncpy(t->dest_addr, dest_addr, max_address_len);
	strncpy(t->origin_addr, origin_addr, max_address_len);
	strncpy(t->t.function_name, function_name, max_func_len);
	strncpy(t->t.on_success, on_success, max_func_len);
	strncpy(t->t.on_failure, on_failure, max_func_len);
	t->param_length = paramlen;
	if(paramlen > 0) memcpy((t+1), param, paramlen);
	//is target machine on this host?
	if(compute::get_address_ip_target(t->dest_addr, nullptr))//if address requires network, add to the comm queue
	{
		talk::add_to_comm_queue(t);
		return true;
	}
	task_queue.acquire()->push(t);
	task_queue.release();
	return true;
}

bool compute::get_priv(unsigned char* pub, unsigned char* priv_out){
	//this O(log N) comparison no longer brings pain to my soul or shame to my descendents
	auto m = local_machines.acquire();
	auto it = m->find(pub_conv(pub));
	if(it == m->end()){
		local_machines.release();
		return false;	
	}
	memcpy(priv_out, it->second.keypair.ecc_priv, ecc_priv_size);
	local_machines.release();
	return true;
}
bool compute::new_machine(const char* name, unsigned char* pub_out){
	//if name is set, it must not be a duplicate
	if(name != nullptr){
		local_machines.acquire();
		if(local_name_index.find(name) != local_name_index.end()){
			local_machines.release();
			return false;
		}
		local_machines.release();
	}
	//gen keypair:
	unsigned char priv[ecc_priv_size];
	crypto::gen_ecdh_keypair(pub_out, priv);
	//fill out machine:
	machine m;
	memcpy(m.keypair.ecc_pub, pub_out, ecc_pub_size);
	memcpy(m.keypair.ecc_priv, priv, ecc_priv_size);
	memset(m.name, 0, max_name_len);
	if(name != nullptr)
		strncpy(m.name, name, max_name_len);
	//save to database:
	recall::acquire_lock();
	//save pub to table:
	int table_len;
	void* table = recall::read("machines_table", &table_len);
	table = realloc(table, table_len+ecc_pub_size);
	memcpy(((char*)table)+table_len, pub_out, ecc_pub_size);
	recall::write("machines_table", table, table_len+ecc_pub_size);
	//save machine
	bytes_to_hex_array(pub_hex, pub_out, ecc_pub_size);
	recall::write(pub_hex, &m, sizeof(machine));
	std::cerr<<"created machine:"<<pub_hex<<"\n";
	free(table);
	recall::release_lock();
	//add to arrays:
	(*local_machines.acquire())[pub_conv(m.keypair.ecc_pub)] = m;
	local_name_index[name] = pub_conv(m.keypair.ecc_pub);
	local_machines.release();
	return true;
}

void* compute::get_wasm(unsigned char* pub, int* length){
	recall::acquire_lock();
	char path[100];
	bytes_to_hex(pub, ecc_pub_size, path);
	strcpy(path+strlen(path), ".wasm");
	void* wasm_data = recall::read(path, length);
	recall::release_lock();
	return wasm_data;
}

void compute::get_root_machine(unsigned char* pub_out){
	local_machines.acquire();
	memcpy(pub_out, local_name_index["root"].key, ecc_pub_size);
	local_machines.release();
}


int locate_address_pivot(const char* address){
	const char* pivot;
	if((pivot = strstr(address, "~")) != nullptr)
		return pivot - address;
	if((pivot = strstr(address, "#")) != nullptr)
		return pivot - address;
	return -1;
}

bool compute::get_address_ip_target(const char* address, char* ip_target_out){
	//std::cerr<<"address:"<<address<<"\n";
	int pivot = locate_address_pivot(address);
	fail_false(pivot > -1); //if pivot is -1, it does not have pivot char
	if(pivot == 0)
		return false;//if pivot is at 0, it is not an error but there is no ip target
	if(ip_target_out != nullptr){
		memcpy(ip_target_out, address, pivot);
		ip_target_out[pivot] = '\0';
	}
	return true;
}
bool compute::get_address_machine_target(const char* address, char* machine_target_out){
	int pivot = locate_address_pivot(address);
	fail_false(pivot > -1);
	strncpy(machine_target_out, address + pivot, max_address_len - pivot);
	return true;
}
bool compute::resolve_local_machine(const char* address, unsigned char* target_pub_out){
	char machine_target[max_address_len];
	fail_false(get_address_machine_target(address, machine_target));
	switch (machine_target[0]){
		case '~':{
			unsigned char tgt_pub[ecc_pub_size];
			hex_to_bytes(machine_target+1, tgt_pub);
			bytes_to_hex_array(hhh, tgt_pub, ecc_pub_size);
			auto ms = local_machines.acquire();
			bool found = false;
			auto it = ms->find(pub_conv(tgt_pub));
			if(it != ms->end()){
				found = true;
				memcpy(target_pub_out, tgt_pub, ecc_pub_size);
			}
			local_machines.release();
			return found;
		}
		case '#':{
			local_machines.acquire();
			auto it = local_name_index.find(machine_target+1);
			if(it == local_name_index.end()){
				local_machines.release();
				fail_false(false);
			}
			memcpy(target_pub_out, it->second.key, ecc_pub_size);
			local_machines.release();
			return true;
		}
	}
	std::cerr<<"unrecognised leading char:"<<machine_target[0];
	return false;
}