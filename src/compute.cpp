#include <queue>
#include <vector>
#include <cstring>
#include <pthread.h>
#include <unistd.h>

#include "../include/platform.h"

struct pub_key{
	unsigned char key[ecc_pub_size];
	bool operator< (const pub_key oth){
		return memcmp(key, oth.key, ecc_pub_size) < 0;
	}
};
bool operator< (const pub_key k1, const pub_key k2){
	return memcmp(k1.key, k2.key, ecc_pub_size) < 0;
}
pub_key pub_conv(unsigned char* p){
	return *(pub_key*)p;
}

thread::locker<std::queue<host_task*>> task_queue;
thread::locker<std::map<pub_key, machine>> local_machines;
std::map<std::string, pub_key> local_name_index; //shares local_machines locker (TODO: create struct to lock both in the same locker)
std::map<std::string, intercepts::intercept_func> platform_intercepts;

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
		new_machine("root", new_pub);
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
		(*(found->second.func))({0, nullptr});
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
				compute::copy_to_queue(t->origin_addr, t->dest_addr, call_now, nullptr, nullptr, param, t->ret_len);
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
	if(on_success != nullptr) fail_false(!(strlen(on_success) > max_func_len));
	if(on_failure != nullptr) fail_false(!(strlen(on_failure) > max_func_len));
	fail_false(!(paramlen > max_packet_size));//this probably needs some tuning
	//construt task
	host_task* t = (host_task*)malloc(sizeof(host_task) + paramlen);
	memset(t, 0, sizeof(host_task));//don't want to expose any memory now, do we?
	strncpy(t->dest_addr, dest_addr, max_address_len);
	strncpy(t->origin_addr, origin_addr, max_address_len);
	strncpy(t->t.function_name, function_name, max_func_len);
	if(on_success != nullptr) strncpy(t->t.on_success, on_success, max_func_len);
	if(on_failure != nullptr) strncpy(t->t.on_failure, on_failure, max_func_len);
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

bool compute::get_pub(unsigned char* id, unsigned char* pub_out){
	return false;
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
void compute::new_machine(const char* name, unsigned char* pub_out){
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

	//add to array:
	(*local_machines.acquire())[pub_conv(m.keypair.ecc_pub)] = m;
	local_name_index[name] = pub_conv(m.keypair.ecc_pub);
	local_machines.release();
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


//my god does c/c++ stdlib need a thread-safe, functional way to mess with the working directory
bool path_rel_to(const char* path, const char* rel_to, char* path_out, int path_out_len){
	if (path[0] ==  '/' || path[0] ==  '~'){
		fail_false(strlen(path) < path_out_len);
		strcpy(path_out, path);
		return true;
	}
	fail_false((strlen(path)+strlen(rel_to)+1) < path_out_len);
	strcpy(path_out, rel_to);
	strcpy(path_out+strlen(path_out), "/");
	strcpy(path_out+strlen(path_out), path);
	return true;
}

bool recurse_load_data(cJSON* node, char* current_path, char* cursor, const char* limit, const char* working_directory){
	//get first child:
	cJSON* child = node->child;
	//iterate over children
	while(child){
		//ensure that this child name fits in the buffer, and that it doesn't have an illegal char
		fail_false (strlen(child->string) + cursor < (limit-2));
		fail_false (strstr(".", child->string)==nullptr);
		//add the dot to the buffer
		*cursor = '.';
		cursor++;
		//copy the child name into the buffer
		strcpy(cursor, child->string);
		cursor += strlen(child->string);
		//std::cerr<<current_path<<"\n";
		//if the child is an array, this is a value to be added to the DB
		if(child->type == cJSON_Array){
			//because this is a value, we need to ensure any previous values/children do not exist
			recall::delete_all_with_prefix(current_path);
			//ensure there is at least 1 child, ensure it is the right type
			fail_false(cJSON_GetArraySize(child) > 0);
			cJSON* zeroth = cJSON_GetArrayItem(child, 0);
			fail_false(zeroth->type == cJSON_String);
			//if it is just absent, there is no need to add a value to the DB
			if(strcmp(zeroth->valuestring, "absent") != 0){
				fail_false(cJSON_GetArraySize(child) == 2);
				if(strcmp(zeroth->valuestring, "string") == 0){
					//simplest case: load string as literal
					cJSON* first = cJSON_GetArrayItem(child, 1);
					fail_false(first->type == cJSON_String);
					recall::write(current_path, first->valuestring, strlen(first->valuestring)+1);
				} 
				else if(strcmp(zeroth->valuestring, "hex") == 0){
					//convert hex string to bytes
					cJSON* first = cJSON_GetArrayItem(child, 1);
					fail_false(first->type == cJSON_String);
					int hex_len = strlen(first->valuestring);
					fail_false(strlen(first->valuestring) % 2 == 0); //hex must be even
					unsigned char* to_write = new unsigned char[hex_len/2];
					hex_to_bytes(first->valuestring, to_write);
					recall::write(current_path, to_write, hex_len/2);
				}
				else if(strcmp(zeroth->valuestring, "file") == 0){
					char current_file_path[256];
					//open file pointed to by value, and save it
					cJSON* first = cJSON_GetArrayItem(child, 1);
					fail_false(first->type == cJSON_String);
					int flen;
					fail_false(path_rel_to(first->valuestring, working_directory, current_file_path, sizeof(current_file_path)));
					char* to_write = read_file(current_file_path, &flen);
					recall::write(current_path, to_write, flen);
				} 
				else {
					std::cerr<<"attempt to load prototype data with unkown type:"<<zeroth->valuestring<<"\n";
					return false;
				}
			}
		}
		//if the child is an object, it must be recursed into
		else if(child->type == cJSON_Object){
			if(!recurse_load_data(child, current_path, cursor, limit, working_directory))
				return false;
		}
		//run back the cursor to the parent
		for(; *cursor != '.' && cursor > current_path; cursor--);
		fail_false(cursor > current_path);//COULD SOMEONE OVERWRITE THEIR PUB KEY AND BREAK OUT OF SANDOBOX WITH THIS CHECK???
		//cut off this child
		*cursor = '\0';
		//continue to next iteration
		child = child->next;
	}
	return true;
}

bool compute::load_from_proto_file(const char* manifest_path){
	char manifest_dir[256];
	char* data = nullptr;
	cJSON* json = nullptr;
	int len;
	fail_false(strlen(manifest_path) < sizeof(manifest_dir));
	strcpy(manifest_dir, manifest_path);
	//find last /
	char* last_slash = manifest_dir+strlen(manifest_dir);
	for(;last_slash >= manifest_dir && *last_slash != '/';last_slash--);
	if(last_slash < manifest_dir)
		manifest_dir[0] = '\0';
	else
		*last_slash = '\0';
	data = read_file(manifest_path, &len);
	fail_false(data != nullptr);
	json = cJSON_Parse(data);
	fail_goto(load_from_proto(json, manifest_dir));
	//cleanup on success
	delete data;
	cJSON_Delete(json);
	return true;
	//cleanup on fail:
	fail:
	std::cerr<<"fail\n";
	if(data != nullptr)
		delete data;
	if(json != nullptr)
		cJSON_Delete(json);
	return false;
}
//code to load machine from manifest file into
bool compute::load_from_proto(cJSON* mach, const char* working_dir){
	//find target machine:
	cJSON* target = cJSON_GetObjectItem(mach, "target");
	fail_false(target != nullptr);
	cJSON* mach_type = cJSON_GetObjectItem(target, "type");
	bool targets_root = (mach_type != nullptr) && (mach_type->type == cJSON_String) && (strcmp(mach_type->valuestring, "root") == 0);
	//TODO: add a way to specify the pub
	fail_false(targets_root);//TODO: add a way to target non-root machines
	//TODO: create not currently existing machines
	//check for reset_data:
	char current_node_path[200];
	unsigned char root_pub[ecc_pub_size];
	compute::get_root_machine(root_pub);
	bytes_to_hex(root_pub, ecc_pub_size, current_node_path);
	char* cursor = current_node_path + strlen(current_node_path);
	cJSON* reset_data = cJSON_GetObjectItem(mach, "reset_data");
	if(reset_data != nullptr && reset_data->valueint == true){
		strcpy(cursor, ".");
		recall::delete_all_with_prefix(current_node_path);
		*cursor = '\0';
	}
	//load data:
	cJSON* mach_data = cJSON_GetObjectItem(mach, "data");
	fail_false(recurse_load_data(mach_data, current_node_path, cursor, current_node_path + sizeof(current_node_path), working_dir));
	auto machines = local_machines.acquire();
	//TODO: modify local_machines etc.
	local_machines.release();
	return true;
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
			fail_false(it != local_name_index.end());
			memcpy(target_pub_out, it->second.key, ecc_pub_size);
			return true;
		}
	}
	std::cerr<<"unrecognised leading char:"<<machine_target[0];
	return false;
}