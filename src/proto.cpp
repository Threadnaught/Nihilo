#include <cstring>
#include "../include/platform.h"

extern thread::locker<std::map<compute::pub_key, machine>> local_machines;

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
	char target_name[max_name_len+1];
	char target_pub_hex[(ecc_pub_size*2)+2];
	bool create_new = true;
	strcpy(target_name, "#");
	strcpy(target_pub_hex, "~");
	//find target json:
	cJSON* target = cJSON_GetObjectItem(mach, "target");
	//perform type/bounds checking on name and pub
	if(target != nullptr){
		cJSON* json_name = cJSON_GetObjectItem(target, "name");
		if(json_name != nullptr){
			fail_false(json_name->type == cJSON_String);
			fail_false(strlen(json_name->valuestring) < (sizeof(target_name)-1));
			fail_false(strlen(json_name->valuestring) > 0);
			strcpy(target_name+1, json_name->valuestring);
		}
		cJSON* json_pub = cJSON_GetObjectItem(target, "pub");
		if(json_pub != nullptr){
			fail_false(json_pub->type == cJSON_String);
			fail_false(strlen(json_pub->valuestring) == ecc_pub_size * 2);
			strcpy(target_pub_hex+1, json_pub->valuestring);
		}
	}
	//variables to store resolved public keys:
	unsigned char name_resolved[ecc_pub_size];
	unsigned char pub_resolved[ecc_pub_size];
	bool name_is_found = false;
	bool pub_is_found = false;
	//resolve if set:
	if(strlen(target_name) > 1)
		name_is_found = resolve_local_machine(target_name, name_resolved);
	if(strlen(target_pub_hex) > 1)
		pub_is_found = resolve_local_machine(target_pub_hex, pub_resolved);
	//if pub is set, but corresponding machine is not found, there is no way to recover priv key:
	if(strlen(target_pub_hex) > 1 && !pub_is_found){
		std::cerr<<"Could not find specified pub("<<target_pub_hex+1<<")\n";
		return false;
	}
	//if pub and name resolution result in different machines, the host cannot decide between them
	if((pub_is_found && name_is_found) && (memcmp(name_resolved, pub_resolved, ecc_pub_size) != 0)){
		std::cerr<<"ambiguity between machine specified by name ("<<(target_name+1)<<")and by pub("<<(target_pub_hex+1)<<")\n";
		return false;
	}
	//variable to store single resultant resolved public key
	unsigned char pub[ecc_pub_size];
	if(name_is_found)
		memcpy(pub, name_resolved, ecc_pub_size);
	else if(pub_is_found)
		memcpy(pub, pub_resolved, ecc_pub_size);
	else
	//if neither is found, create a new machine
		fail_false(new_machine(strlen(target_name) > 1?(target_name+1):nullptr, pub));
	char current_node_path[200];
	bytes_to_hex(pub, ecc_pub_size, current_node_path);
	char* cursor = current_node_path + strlen(current_node_path);
	//check for reset_data:
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