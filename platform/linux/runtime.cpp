#include<cstring>

#include "../../include/platform.h"
#include "wasm_export.h"

//TODO: REVIEW POSSIBLE ERROR FROM AMBIGUITY BETWEEN nullptr and strlen() = 0

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
bool copy_sandbox_to_process_str_buffer(char* dest, int dest_len, wasm_module_inst_t module_inst, uint32_t app_offset){
	if(app_offset == 0){
		dest[0] = 0;
		return true;
	}
	//verify passed address addrs belongs to sandbox
	fail_false(wasm_runtime_validate_app_str_addr(module_inst, app_offset));
	//copy from sandbox to process
	char* start = (char*)wasm_runtime_addr_app_to_native(module_inst, app_offset);
	int len = strlen(start)+1;
	fail_false(len <= dest_len);
	memcpy(dest, start, len);
	return true;
}

//TODO: exit out of runtime in set_return??

//API implementation:
bool set_return(wasm_exec_env_t exec_env, int32_t success, uint32_t ret, int32_t ret_len){
	//std::cerr<<"ret:"<<ret<<" ret length:"<<ret_len<<"\n";
	host_task* t = (host_task*)wasm_runtime_get_user_data(exec_env);
	t->success = success;
	//if there is a previous ret, delete it
	if(t->ret_len > 0){
		delete t->ret;
		t->ret = nullptr;
		t->ret_len = 0;
	}
	//if there is a new ret, copy it out of sandbox mem
	if(ret_len > 0){
		unsigned char* tgt = new unsigned char[ret_len];
		if(copy_sandbox_to_process(tgt, (wasm_module_inst_t)t->env_inst, ret, ret_len)) {
			t->ret = tgt;
			t->ret_len = ret_len;
			//std::cerr<<"set\n";
		}
		else {
			delete tgt;
			std::cerr<<"not set\n";
			return false;
		}
	}
	return true;
}

bool queue(wasm_exec_env_t exec_env, uint32_t dest, uint32_t func_name, uint32_t on_success, uint32_t on_failure, uint32_t param, uint32_t param_length){
	host_task* t = (host_task*)wasm_runtime_get_user_data(exec_env);
	char dest_buf[max_address_len];
	fail_false(copy_sandbox_to_process_str_buffer(dest_buf, max_address_len, (wasm_module_inst_t)t->env_inst, dest));
	char func_buf[max_func_len];
	fail_false(copy_sandbox_to_process_str_buffer(func_buf, max_address_len, (wasm_module_inst_t)t->env_inst, func_name));
	char success_buf[max_func_len];
	fail_false(copy_sandbox_to_process_str_buffer(success_buf, max_address_len, (wasm_module_inst_t)t->env_inst, on_success));
	char fail_buf[max_func_len];
	fail_false(copy_sandbox_to_process_str_buffer(fail_buf, max_address_len, (wasm_module_inst_t)t->env_inst, on_failure));
	unsigned char* param_buf = nullptr;
	if(param_length > 0){
		param_buf = new unsigned char[param_length];
		fail_false(copy_sandbox_to_process(param_buf, (wasm_module_inst_t)t->env_inst, param, param_length));
	}
	fail_false(compute::copy_to_queue(dest_buf, t->dest_addr, func_buf, (strlen(success_buf)>0)?success_buf:nullptr, (strlen(fail_buf)>0)?fail_buf:nullptr, param_buf, param_length));
	delete param_buf;
	return true;
}

NativeSymbol nih_symbols[] =
	{
		{
			"set_return",
			(void*)set_return,
			"(iii)i",
			NULL
		},
		{
			"queue",
			(void*)queue,
			"(iiiiii)i",//uint32_t dest, uint32_t func_name, uint32_t on_success, uint32_t on_failure, uint32_t param, uint32_t param_length
			NULL
		}
};

bool runtime::init(){
	fail_false(wasm_runtime_init());
	wasm_runtime_register_natives("env", nih_symbols, sizeof(nih_symbols) / sizeof(NativeSymbol));
	return true;
}
bool runtime::exec_task(host_task* t){
	hex_to_bytes_array(target_pub, t->dest_addr, ecc_pub_size);
	int buf_len;
	unsigned char* buf = compute::get_wasm(target_pub, &buf_len);
	char error_buf[128];
	error_buf[0] = 0;
	wasm_module_t mod = wasm_runtime_load(buf, buf_len, error_buf, sizeof(error_buf));
	wasm_module_inst_t inst = wasm_runtime_instantiate(mod, 8092, 8092, error_buf, sizeof(error_buf));
	//lookup the function:
	wasm_function_inst_t func = wasm_runtime_lookup_function(inst, t->t.function_name, NULL);
	if(func == nullptr){
		std::cerr<<"Could not find function named "<<t->t.function_name<<"\n";
		return false;
	}
	wasm_exec_env_t e_env = wasm_runtime_create_exec_env(inst, 8092);
	//attach task to runtime:
	wasm_runtime_set_user_data(e_env, t);
	t->env_inst = inst;
	unsigned int argv[1];
	uint32_t param;
	if(t->param_length > 0){
		fail_false(copy_process_to_sandbox(&param, inst, ((unsigned char*)t)+sizeof(host_task), t->param_length));
		argv[0] = param;
	} else{
		argv[0] = 0;
	}
	fail_false(wasm_runtime_call_wasm(e_env, func, 1, argv));
	std::cerr<<"";//flush prints to docker
	wasm_runtime_destroy_exec_env(e_env);
	wasm_runtime_deinstantiate(inst);
	wasm_runtime_unload(mod);
	return true;
}