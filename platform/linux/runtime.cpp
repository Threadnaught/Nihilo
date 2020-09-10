#include"../../include/platform.h"
#include "wasm_export.h"

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
	std::cerr<<"load err:"<<error_buf<<"\n";
	error_buf[0] = 0;
	wasm_module_inst_t inst = wasm_runtime_instantiate(mod, 8092, 8092, error_buf, sizeof(error_buf));
	std::cerr<<"load err:"<<error_buf<<"\n";
	error_buf[0] = 0;
	std::cerr<<"doing work!\n";
	//lookup the function:
	wasm_function_inst_t func = wasm_runtime_lookup_function(inst, "calculate", NULL);
	if(func == nullptr){
		std::cerr<<"fuck\n";
		return false;
	}
	wasm_exec_env_t e_env = wasm_runtime_create_exec_env(inst, 8092);
	unsigned int argv[2];
	
	wasm_runtime_call_wasm(e_env, func, 1, argv);
	wasm_runtime_destroy_exec_env(e_env);
	wasm_runtime_deinstantiate(inst);
	wasm_runtime_unload(mod);
	return true;
}