#include <queue>

#include "../include/platform.h"

thread::locker<std::queue<task>> comm_queue(std::queue<task>());

void talk::init(int port){

}

void run_talk_worker(){
	while(1){
		//empty comm queue
		//wait for incomming connection (or timeout)
		//receive header (or timeout)
		//receive body (or timeout)
		//close connection
		//queue task
	}
}