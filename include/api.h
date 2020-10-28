#include <stdint.h>

//TODO: unsigned char* --> void* (FINISHED FOR THIS FILE BUT NOT ELSEWHERE)

//add a function call to the queue
int queue(const char* dest, const char* func_name, const char* on_success, const char* on_failure, const void* param, uint32_t param_length);
//add a function call to the queue with a string param
int queue_str(const char* dest, const char* func_name, const char* on_success, const char* on_failure, const char* param){
	return queue(dest, func_name, on_success, on_failure, param, strlen(param)+1);
}
//write write_length bytes of to_write to this machines db at path
int write_DB(const char* path, const void* to_write, uint32_t write_length);
//read from path, return the data found, and write the data length to read_length
void* read_DB(const char* path, uint32_t* read_length);
//set return value
int set_return(int success, const void* ret, uint32_t ret_len);