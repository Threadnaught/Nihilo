#include <queue>

#include "../include/platform.h"

thread::locker<std::queue<task>> task_queue(std::queue<task>());

void compute::init(int thread_count){

}

void run_compute_worker(){
	while(1){
		//remove task from queue
		//load wasm
		//execute wasm (using platform exec)
	}
}