#include <queue>
#include <vector>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <cstring>
#include <unistd.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <time.h>

#include "../include/platform.h"

thread::locker<std::queue<task>> comm_queue(std::queue<task>());

struct open_connection{
	int fd;
	sockaddr_in addr; 
	time_t timeout;//TODO
	bool is_packet_waiting;
	packet_header waiting_packet;
};

std::vector<open_connection> open_connections;

void drop(int con_no){
	shutdown(open_connections[con_no].fd, SHUT_RDWR);
	close(open_connections[con_no].fd);
	open_connections.erase(open_connections.begin() + con_no);
}

bool run_talk_worker(int port){
	//create listener:
	int listener_no = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	fail_false(listener_no > 0);

	//configure inbound endpoint:
	sockaddr_in addr;
	memset(&addr, 0, sizeof(sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	//bind inbound endpoint:
	fail_false(bind(listener_no, (sockaddr*)&addr, sizeof(sockaddr_in)) == 0);
	listen(listener_no,5);
	std::cout<<"listening\n";
	while(1){
		//transmit comm queue
		//poll fresh incoming connections:
		pollfd polls;
		polls.fd = listener_no;
		polls.events = POLLIN;
		polls.revents = 0;
		poll(&polls, open_connections.size()+1, 0);
		//if there is an incoming connection...
		if(polls.revents != 0){
			open_connection con;
			socklen_t other_len = sizeof(sockaddr_in);
			//accept the connection
			int connection_no = accept(listener_no, (sockaddr*) &con.addr, &other_len);
			//if the connection is valid, add it to the list and reset its timeout
			if(connection_no >= 0){
				con.fd = connection_no;
				con.timeout = time(NULL) + con_timeout;
				open_connections.push_back(con);
			}
		}
		//iterate over known connections
		for(int i = 0; i < open_connections.size(); i++){
			//count waiting bytes
			int count;
			ioctl(open_connections[i].fd, FIONREAD, &count);
			if(count > 0){
				//if no packet is currently waiting, and a header is in the pipe...
				if((!open_connections[i].is_packet_waiting) && count >= sizeof(packet_header)){
					//read the header
					read(open_connections[i].fd, &open_connections[i].waiting_packet, sizeof(packet_header));
					//if the packet is too long, drop the connection
					if(open_connections[i].waiting_packet.contents_length > max_packet_size){
						std::cout<<"dropping (packet too long)\n";
						drop(i--);
						continue;
					}
					//if not, set packet is waiting and bump the timeout
					open_connections[i].is_packet_waiting = true;
					open_connections[i].timeout = time(NULL) + con_timeout;
				}
				//if a packet is waiting, and a body is in the pipe
				if(open_connections[i].is_packet_waiting && count >= open_connections[i].waiting_packet.contents_length){
					std::cout<<"receiving body\n";
					//read it off the pipe
					char* inbuf = new char[crypto::calc_encrypted_size(open_connections[i].waiting_packet.contents_length)];
					read(open_connections[i].fd, inbuf, crypto::calc_encrypted_size(open_connections[i].waiting_packet.contents_length));
					delete inbuf;//TODO: do something with it
					open_connections[i].is_packet_waiting = false;
					open_connections[i].timeout = time(NULL) + con_timeout;
				}
			}
			//if connection has timed out, drop it
			if(open_connections[i].timeout < time(NULL)){
				std::cout<<"dropping (timeout)\n";
				drop(i--);
				continue;
			}
		}

	}
}

void talk::init(int port){
	run_talk_worker(port);//TODO: threading
}

