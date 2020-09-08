#include"../../include/platform.h"
#include "wasm_export.h"

bool runtime::init(){
	fail_false(wasm_runtime_init());
	return true;
}
void runtime::exec_task(host_task* t){
	hex_to_bytes_array(target_pub, t->dest_addr, ecc_pub_size);
	int buf_len;
	unsigned char* buf = compute::get_wasm(target_pub, &buf_len);
	char error_buf[128];
	wasm_module_t mod = wasm_runtime_load(buf, buf_len, error_buf, sizeof(error_buf));
	wasm_module_inst_t inst = wasm_runtime_instantiate(mod, 8092, 8092, error_buf, sizeof(error_buf));
	std::cerr<<"doing work!\n";

	wasm_runtime_deinstantiate(inst);
	wasm_runtime_unload(mod);
}