#include<cstring>

#include "../../include/platform.h"
#include "wasm_export.h"

bool copy_process_to_sandbox(uint32_t* dest, wasm_module_inst_t module_inst, const unsigned char *src, uint32_t size){
	//this is where the magic happens
	uint32_t ret = wasm_runtime_module_dup_data(module_inst, (const char*)src, size);
	fail_false(ret != 0);
	(*dest) = ret;
	return true;
}
bool copy_sandbox_to_process(unsigned char* dest, wasm_module_inst_t module_inst, uint32_t app_offset, uint32_t size){
	//verify passed address addrs belongs to sandbox
	fail_false(wasm_runtime_validate_app_addr(module_inst, app_offset, size));
	//copy from sandbox to process
	void* start = wasm_runtime_addr_app_to_native(module_inst, app_offset);
	memcpy(dest, start, size);
	return true;
}


bool runtime::init(){
	fail_false(wasm_runtime_init());
	return true;
}
bool runtime::exec_task(host_task* t){
	hex_to_bytes_array(target_pub, t->dest_addr, ecc_pub_size);
	int buf_len;
	unsigned char* buf = compute::get_wasm(target_pub, &buf_len);
	char error_buf[128];
	error_buf[0] = 0;
	wasm_module_t mod = wasm_runtime_load(buf, buf_len, error_buf, sizeof(error_buf));
	if(error_buf[0] != 0)
		std::cerr<<"load err:"<<error_buf<<"\n";
	error_buf[0] = 0;
	wasm_module_inst_t inst = wasm_runtime_instantiate(mod, 8092, 8092, error_buf, sizeof(error_buf));
	if(error_buf[0] != 0)
		std::cerr<<"load err:"<<error_buf<<"\n";
	error_buf[0] = 0;
	//lookup the function:
	wasm_function_inst_t func = wasm_runtime_lookup_function(inst, t->t.function_name, NULL);
	if(func == nullptr){
		std::cerr<<"fuck\n";
		return false;
	}
	wasm_exec_env_t e_env = wasm_runtime_create_exec_env(inst, 8092);
	unsigned int argv[1];
	if(!wasm_runtime_call_wasm(e_env, func, 0, argv)){
		std::cerr<<"fuckfuckfuck\n";
		return false;
	}
	std::cerr<<"done\n";//flush prints to docker
	wasm_runtime_destroy_exec_env(e_env);
	wasm_runtime_deinstantiate(inst);
	wasm_runtime_unload(mod);
	return true;
}