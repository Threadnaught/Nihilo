#include"../../include/platform.h"

using namespace intercepts;

intercept_param test_func(intercept_param param){
	std::cerr<<"called into interceptor\n";
	return {0, nullptr};
}

void intercepts::register_intercepts(std::map<std::string, intercept_func>& map){
	map["interceptor"] = {"interceptor", &test_func};
}