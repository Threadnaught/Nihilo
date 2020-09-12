#include <stdint.h>

//add a function call to the correct queue
void queue(const char* dest, const char* func_name, const char* on_success, const char* on_failure, const unsigned char* param, uint32_t param_length);
//write write_length bytes of to_write to this machines db at path
void write_DB(const char* path, const unsigned char* to_write, uint32_t write_length);
//read from path, return the data found, and write the data length to read_length
unsigned char* read_DB(const char* path, uint32_t* read_length);
//set return value
void set_return(int success, const unsigned char* ret, uint32_t ret_len);
