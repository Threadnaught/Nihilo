#include"../../include/platform.h"
#include <microhttpd.h>
#include<cstring>

#define resource_id_size 16

using namespace intercepts;

void test_func(host_task* t){
	std::cerr<<"called into interceptor\n";
	t->success = 1;
	t->ret_len = 0;
}

//<HTTP TEMPORARY SOLUTION>
//I WANT TO REPLACE THIS WITH A NIHILO GENERIC CONNECTION MANAGER AND LLPARSE COMPILED INTO WASM
struct HTTP_Daemon{
	MHD_Daemon * d;
	char handler_func[max_func_len];
	char handler_address[max_address_len];
	char server_address[max_address_len];
};
struct HTTP_Connection{
	MHD_Connection* c;
	bool response_set;
	MHD_Response* to_send;
};

thread::locker<std::map<std::array<unsigned char, resource_id_size>, HTTP_Daemon>> daemons;
thread::locker<std::map<std::array<unsigned char, resource_id_size>, HTTP_Connection*>> connections;

int http_handler(void * cls,
	struct MHD_Connection * connection,
	const char * url,
	const char * method,
	const char * version,
	const char * upload_data,
	size_t * upload_data_size,
	void ** ptr) {
	char queue_param[1000];
	bytes_to_hex_array(daemon_hex, (unsigned char*)cls, resource_id_size);
	std::array<unsigned char, resource_id_size> connection_id;
	crypto::rng(nullptr, connection_id.data(), resource_id_size);
	bytes_to_hex_array(con_hex, connection_id.data(), resource_id_size);
	snprintf(queue_param, sizeof(queue_param), "%s/%s/%s/%s", con_hex, daemon_hex, method, url);
	auto cs = connections.acquire();
	HTTP_Connection* con = new HTTP_Connection{.c=connection, .response_set=false};
	(*cs)[connection_id] = con;
	connections.release();
	auto ds = daemons.acquire();
	std::array<unsigned char, resource_id_size> daemon_id;
	memcpy(daemon_id.data(), cls, resource_id_size);
	HTTP_Daemon d = (*ds)[daemon_id];
	daemons.release();
	compute::copy_to_queue(d.handler_address, d.server_address, d.handler_func, "http_respond", nullptr, queue_param, strlen(queue_param)+1);
	while(!con->response_set)usleep(20000);
	int queue_ret = MHD_queue_response(connection, MHD_HTTP_OK, con->to_send);
	MHD_destroy_response(con->to_send);
	delete con;
	return queue_ret;
}

void http_register(host_task* t){
	if(t->param_length == 0 || t->param_length >= max_func_len || *(((char*)t)+sizeof(t)+t->param_length) != '\0'){//ensure min, max and null-terminated
		t->success = 0;
		t->ret_len = 0;
		return;
	}
	std::array<unsigned char, resource_id_size> daemon_key;
	crypto::rng(nullptr, daemon_key.data(), resource_id_size);
	auto ds = daemons.acquire();
	HTTP_Daemon d;
	d.d = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION | MHD_USE_SUSPEND_RESUME, 8080, NULL, NULL, &http_handler, daemon_key.data(), MHD_OPTION_END);
	strcpy(d.handler_address, t->origin_addr);
	strcpy(d.server_address, t->dest_addr);
	strcpy(d.handler_func, ((char*)t)+sizeof(host_task));
	(*ds)[daemon_key] = d;
	daemons.release();
	char* daemon_key_hex = new char[(resource_id_size*2)+1];
	bytes_to_hex(daemon_key.data(), resource_id_size, daemon_key_hex);
	t->success = 1;
	t->ret = daemon_key_hex;
	t->ret_len = (resource_id_size*2)+1;
}

void http_unregister(host_task* t){
	//TODO
	t->success = 0;
	t->ret_len = 0;
}

void http_respond(host_task* t){
	char* param = (char*)(t+1);
	if(t->param_length < (resource_id_size*2)+2 || strnlen(param, t->param_length) == t->param_length){//ensure min, max and null-terminated
		t->success = 0;
		t->ret_len = 0;
		return;
	}
	if(param[(resource_id_size*2)] != '/'){ //ensure has hex seperating
		t->success = 0;
		t->ret_len = 0;
		return;
	}
	for(int i = 0; i < resource_id_size*2; i++){//enforce hex
		if((!(param[i] >= '0' && param[i] <= '9')) &&
		(!(param[i] >= 'a' && param[i] <= 'f')) &&
		(!(param[i] >= 'A' && param[i] <= 'F'))){
			t->success = 0;
			t->ret_len = 0;
			return;
		}
	}
	param[resource_id_size*2] = '\0';
	std::array<unsigned char, resource_id_size> connection_id;
	hex_to_bytes(param, connection_id.data());
	param[resource_id_size*2] = '/';
	auto cs = connections.acquire();
	auto it = cs->find(connection_id);
	if(it == cs->end()){
		std::cerr<<"couldn't find HTTP connection\n";
		t->success = 0;
		t->ret_len = 0;
		connections.release();
		return;
	}
	it->second->to_send = MHD_create_response_from_buffer (t->param_length-(resource_id_size*2)-2, param+(resource_id_size*2)+1, MHD_RESPMEM_PERSISTENT);
	it->second->response_set = true;
	cs->erase(it);
	connections.release();
	t->success = 1;
	t->ret_len = 0;
}
//</HTTP TEMPORARY SOLUTION>
void intercepts::register_intercepts(std::map<std::string, intercept_func>& map){
	map["interceptor"] = {&test_func};
	map["http_register"] = {&http_register};
	map["http_respond"] = {&http_respond};
}