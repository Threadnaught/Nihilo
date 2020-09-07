#include <queue>
#include <vector>
#include <cstring>

#include "../include/platform.h"

thread::locker<std::queue<host_task*>> task_queue;
thread::locker<std::vector<machine>> local_machines;

bool compute::init(){
	//load machines into local_machines:
	int table_len;
	unsigned char* table = recall::read("machines_table", &table_len);
	//if the table cannot be found, recreate db
	if(table == nullptr){
		std::cerr<<"recreating DB\n";
		unsigned char c;
		recall::write("machines_table", &c, 0);
		unsigned char new_pub[ecc_pub_size];
		new_machine(new_pub);
		table = recall::read("machines_table", &table_len);
	}
	//std::cerr<<"table size: "<<table_len<<"\n";
	fail_false(table_len % ecc_pub_size == 0);
	auto locals = local_machines.acquire();
	for(int i = 0; i < table_len; i += ecc_pub_size){
		int m_len;
		bytes_to_hex_array(pub_hex, table + i, ecc_pub_size);
		//std::cerr<<"loading machine "<<pub_hex<<"\n";
		machine* m = (machine*)recall::read(pub_hex, &m_len);
		fail_false(m_len == sizeof(machine));
		locals->push_back(*m);
	}
	local_machines.release();
	delete table;
	return true;
}

void compute::launch_threads(int thread_count){
	
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
	std::cerr<<"Sending "<<function_name<<" to "<<dest_addr<<"\n";
	fail_false(!(strlen(dest_addr) > max_address_len));
	fail_false(!(strlen(function_name) > max_func_len));
	if(on_success != nullptr) fail_false(!(strlen(on_success) > max_func_len));
	if(on_failure != nullptr) fail_false(!(strlen(on_failure) > max_func_len));
	fail_false(!(paramlen > max_packet_size));//this probably needs some tuning
	//construt task
	host_task* t = (host_task*)malloc(sizeof(host_task) + paramlen);
	memset(t, 0, sizeof(host_task));//don't want to expose any memory now, do we?
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
	//gen keypair:
	unsigned char priv[ecc_priv_size];
	crypto::gen_ecdh_keypair(pub_out, priv);
	//fill out machine:
	machine m;
	memcpy(m.keypair.ecc_pub, pub_out, ecc_pub_size);
	memcpy(m.keypair.ecc_priv, priv, ecc_priv_size);
	crypto::id_from_pub(pub_out, m.ID);
	//add to array:
	local_machines.acquire()->push_back(m);
	local_machines.release();
	//save to database:
	recall::acquire_lock();
	//save pub to table:
	int table_len;
	unsigned char* table = recall::read("machines_table", &table_len);
	table = (unsigned char*)realloc(table, table_len+ecc_pub_size);
	memcpy(table+table_len, pub_out, ecc_pub_size);
	recall::write("machines_table", table, table_len+ecc_pub_size);
	//save machine
	bytes_to_hex_array(pub_hex, pub_out, ecc_pub_size);
	recall::write(pub_hex, (unsigned char*)&m, sizeof(machine));
	delete table;
	recall::release_lock();
	//TODO: ADD TO DB
}

bool compute::save_wasm(unsigned char* pub, unsigned char* wasm, int length){
	recall::acquire_lock();
	char path[100];
	bytes_to_hex(pub, ecc_pub_size, path);
	strcpy(path+strlen(path), ".wasm");
	fail_false(recall::write(path, wasm, length));
	recall::release_lock();
	return true;
}
unsigned char* compute::get_wasm(unsigned char* pub, int* length){
	recall::acquire_lock();
	char path[100];
	bytes_to_hex(pub, ecc_pub_size, path);
	strcpy(path+strlen(path), ".wasm");
	unsigned char* wasm_data = recall::read(path, length);
	recall::release_lock();
	return wasm_data;
}

void compute::get_default_machine(unsigned char* pub_out){
	memcpy(pub_out, local_machines.acquire()->at(0).keypair.ecc_pub, ecc_pub_size);
	local_machines.release();
}