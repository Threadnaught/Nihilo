#include <queue>
#include <vector>
#include <cstring>
#include <pthread.h>
#include <unistd.h>

#include <cjson/cJSON.h>
#include "../include/platform.h"

thread::locker<std::queue<host_task*>> task_queue;
thread::locker<std::vector<machine>> local_machines;
unsigned char root_pub[ecc_pub_size];
std::map<std::string, intercepts::intercept_func> platform_intercepts;

void delete_task(host_task* t){
	if(t->ret_len > 0){
		delete t->ret;
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
		new_machine(new_pub, true);
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
		locals->push_back(*m);
		if(locals->size() == 1){//first machine, clearly the root TODO: create a db-wide config and make this more better
			memcpy(root_pub, m->keypair.ecc_pub, ecc_pub_size);
		}
	}
	local_machines.release();
	delete table;
	intercepts::register_intercepts(platform_intercepts);
	//std::cerr<<"intercepts:"<<platform_intercepts.size()<<"\n";
	return true;
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
			//FIRST: check if this call is intercepted
			//this behaviour is duplicated in exec_task
			//TODO: move all this shit to host_task init
			char* dest_pub = t->dest_addr;
			if(strstr(dest_pub, "~") != nullptr){
				dest_pub = strstr(dest_pub, "~")+1;
			}
			hex_to_bytes_array(dest_pub_bytes, dest_pub, ecc_pub_size);
			auto found = platform_intercepts.find(t->t.function_name);
			//std::cerr<<"fname:"<<platform_intercepts.size()<<"\n";

			if(memcmp(root_pub, dest_pub_bytes, ecc_pub_size) == 0 && found != platform_intercepts.end()){//check for intercepts
				(*(found->second.func))({0, nullptr});
				delete_task(t);
			} else {
				//SECOND: If this call is not intercepted, go through normal call
				if(runtime::exec_task(t)){
					//std::cerr<<"successful\n";
					//if there is a on_success event, copy to the queue
					if(strlen(t->t.on_success) > 0){
						//if there is a return value, set it as the param, and if not call without
						if(t->ret_len > 0){
							compute::copy_to_queue(t->origin_addr, t->dest_addr, t->t.on_success, nullptr, nullptr, t->ret, t->ret_len);
						} else {
							compute::copy_to_queue(t->origin_addr, t->dest_addr, t->t.on_success, nullptr, nullptr, nullptr, 0);
						}
					}
					delete_task(t);
				} else {
					if(++t->retry_count >= max_retries){
						if(strlen(t->t.on_failure) > 0)
							compute::copy_to_queue(t->origin_addr, t->dest_addr, t->t.on_failure, nullptr, nullptr, nullptr, 0);
						delete_task(t);
					} else {
						task_queue.acquire()->push(t);
						task_queue.release();
					}
				}
			}
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
void compute::new_machine(unsigned char* pub_out, bool root){
	//gen keypair:
	unsigned char priv[ecc_priv_size];
	crypto::gen_ecdh_keypair(pub_out, priv);
	//fill out machine:
	machine m;
	m.root = root;
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
	unsigned char* table = (unsigned char*)recall::read("machines_table", &table_len);
	table = (unsigned char*)realloc(table, table_len+ecc_pub_size);
	memcpy(table+table_len, pub_out, ecc_pub_size);
	recall::write("machines_table", table, table_len+ecc_pub_size);
	//save machine
	bytes_to_hex_array(pub_hex, pub_out, ecc_pub_size);
	recall::write(pub_hex, (unsigned char*)&m, sizeof(machine));
	std::cerr<<"created machine:"<<pub_hex<<"\n";
	delete table;
	recall::release_lock();
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
	unsigned char* wasm_data = (unsigned char*)recall::read(path, length);
	recall::release_lock();
	return wasm_data;
}

void compute::get_default_machine(unsigned char* pub_out){
	memcpy(pub_out, local_machines.acquire()->at(0).keypair.ecc_pub, ecc_pub_size);
	local_machines.release();
}
bool recurse_load_data(cJSON* node, char* current_path, char* cursor, const char* limit){
	//get first child:
	cJSON* child = node->child;
	//iterate over children
	while(child){
		//ensure that this child name fits in the buffer, and that it doesn't have an illegal char
		fail_false (strlen(child->string) + cursor < (limit-2)) 
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
					//open file pointed to by value, and save it
					cJSON* first = cJSON_GetArrayItem(child, 1);
					fail_false(first->type == cJSON_String);
					int flen;
					char* to_write = read_file(first->valuestring, &flen);
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
			if(!recurse_load_data(child, current_path, cursor, limit))
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
//code to load machine from manifest file into
bool compute::load_from_proto(const char* proto_path){
	//move over working directory
	char working_dir[512];
	fail_false(getcwd(working_dir, sizeof(working_dir)) != nullptr);//this could be the source of problems on microcontrollers
	fail_false(chdir(proto_path) != -1);
	//load manifest:
	int len;
	char* data = read_file("manifest.json", &len);
	cJSON* json = cJSON_Parse(data);//TODO:non zero termination??????????
	//find target machine:
	cJSON* mach = cJSON_GetObjectItem(json, "target");
	fail_false(mach != nullptr);
	cJSON* mach_type = cJSON_GetObjectItem(mach, "type");
	bool targets_root = (mach_type != nullptr) && (mach_type->type == cJSON_String) && (strcmp(mach_type->valuestring, "root") == 0);
	//TODO: add a way to specify the pub
	fail_false(targets_root);//TODO: add a way to target non-root machines
	auto machines = local_machines.acquire();
	int target = -1;
	for(int i = 0; i < machines->size(); i++)
		if((*machines)[i].root){
			target = i;
			break;
		}
	
	//TODO: create not currently existing machines
	fail_false(target >= 0);
	//check for reset_data:
	char current_node_path[200];
	bytes_to_hex((*machines)[target].keypair.ecc_pub, ecc_pub_size, current_node_path);
	char* cursor = current_node_path + strlen(current_node_path);
	cJSON* reset_data = cJSON_GetObjectItem(json, "reset_data");
	if(reset_data != nullptr && reset_data->valueint == true){
		strcpy(cursor, ".");
		recall::delete_all_with_prefix(current_node_path);
		*cursor = '\0';
	}
	//load data:
	cJSON* mach_data = cJSON_GetObjectItem(json, "data");
	fail_false(recurse_load_data(mach_data, current_node_path, cursor, current_node_path + sizeof(current_node_path)));
	local_machines.release();
	fail_false(chdir(working_dir) != -1);
	//TODO: create cleanup GOTO (cJSON delete, reset working directory, memory cleanup)
	return true;
}