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
#include <cstring>

#include "../include/platform.h"

thread::locker<std::queue<host_task*>> comm_queue;

struct host{
	int fd;
	sockaddr_in addr; 
	time_t timeout;//TODO
	bool is_packet_waiting;
	packet_header waiting_packet;
	std::vector<machine> known_machines;
};

std::vector<host> hosts;

bool send_comm(host_task* t){ //THREAD UNSAFE, ONLY TO BE CALLED FROM THE TALK WORKER THREAD
	//std::cerr<<"calling "<<t->t.function_name<<" on "<<t->dest_addr<<"\n";
	//split hostname/machine identifier
	char hostname[max_address_len];
	memcpy(hostname, t->dest_addr, max_address_len);
	char* identifier = strstr(hostname, "~");
	identifier[0] = '\0';
	identifier++;
	//std::cerr<<"hostname: "<<hostname<<" identifier: "<<identifier<<"\n";
	//TODO: PORT, ALIASES, CHAINING ETC.
	//open socket:
	int connection_no = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	fail_false(connection_no >= 0);
	//DNS/IP lookup:
	hostent* target_ent = gethostbyname(hostname);
	fail_false(target_ent != nullptr);
	//fresh_con ONLY USEFUL FOR A FRESH CONNECTION, USE host_index FOR EITHER A FOUND OR FRESH CONNECTION
	host fresh_con;
	memset(&fresh_con.addr, 0, sizeof(sockaddr_in));
	fresh_con.addr.sin_family = AF_INET;
	memcpy(&fresh_con.addr.sin_addr.s_addr, target_ent->h_addr_list[0], target_ent->h_length);
	fresh_con.addr.sin_port = htons(tcp_port);
	//check for already established connection:
	int host_index = -1;
	for(int i = 0; i < hosts.size(); i++)
		if((fresh_con.addr.sin_addr.s_addr == hosts[i].addr.sin_addr.s_addr) && (fresh_con.addr.sin_port == hosts[i].addr.sin_port)){
			//std::cerr<<"found!\n";
			host_index = i;
			break;
		}
	//if there is no already established connection, connect
	if(host_index == -1){
		fail_false(connect(connection_no, (sockaddr*)&fresh_con.addr, sizeof(sockaddr_in)) >= 0);
		fresh_con.fd = connection_no;
		hosts.push_back(fresh_con);
		host_index = hosts.size() - 1;
		//std::cerr<<"established!\n";
	}
	//reset timeout:
	hosts[host_index].timeout = time(NULL) + con_timeout;
	//derrive shared secret:
	hex_to_bytes_array(receiver_pub, identifier, ecc_pub_size);
	unsigned char sender_priv[ecc_priv_size];
	fail_false(compute::get_priv(t->origin_pub, sender_priv));
	unsigned char secret[shared_secret_size];
	fail_false(crypto::derrive_shared(sender_priv, receiver_pub, secret));
	//construct and send header:
	packet_header header;
	memcpy(header.origin_pub, t->origin_pub, ecc_pub_size);
	memcpy(header.dest_pub, receiver_pub, ecc_pub_size);
	header.contents_length = sizeof(wire_task) + t->param_length;
	fail_false(write(hosts[host_index].fd, (void*)&header, sizeof(packet_header)) >= 0);
	std::cerr<<"wrote header\n";
	//construct body:
	int encrypted_buffer_size = crypto::calc_encrypted_size(header.contents_length);
	//rounded to the nearest block, but without IV
	int unencrypted_buffer_size = encrypted_buffer_size - aes_block_size;
	unsigned char* unencrypted = new unsigned char[unencrypted_buffer_size];
	//don't want to expose memory to peer
	memset(unencrypted, 0, unencrypted_buffer_size);
	wire_task* wire = (wire_task*)unencrypted;
	//copy over target id/task info/param
	fail_false(crypto::id_from_pub(header.dest_pub, wire->target_ID));
	memcpy(&wire->t, &t->t, sizeof(common_task));
	if(t->param_length > 0)
		memcpy(unencrypted+sizeof(wire_task), ((char*)t)+sizeof(host_task), t->param_length);
	//encrypt and send body:
	unsigned char* encrypted = new unsigned char[encrypted_buffer_size];
	fail_false(crypto::encrypt(secret, unencrypted, unencrypted_buffer_size, encrypted));
	fail_false(write(hosts[host_index].fd, encrypted, encrypted_buffer_size) >= 0);
	//memory cleanup:
	delete encrypted;
	delete unencrypted;//TODO: fix failure memory leak (maybe create a goto)
	delete t;
	return true;
}

void drop(int con_no){
	shutdown(hosts[con_no].fd, SHUT_RDWR);
	close(hosts[con_no].fd);
	hosts.erase(hosts.begin() + con_no);
}

bool receive_body(int hostid, unsigned char* body){
	std::cerr<<"receiving body\n";
	unsigned char dest_priv[ecc_priv_size];
	fail_false(compute::get_priv(hosts[hostid].waiting_packet.dest_pub, dest_priv));
	unsigned char secret[shared_secret_size];
	crypto::derrive_shared(dest_priv, hosts[hostid].waiting_packet.origin_pub, secret);
	int encrypted_buffer_size = crypto::calc_encrypted_size(hosts[hostid].waiting_packet.contents_length);
	//rounded to the nearest block, but without IV
	int unencrypted_buffer_size = encrypted_buffer_size - aes_block_size;
	unsigned char* unencrypted = new unsigned char[unencrypted_buffer_size];
	fail_false(crypto::decrypt(secret, body, unencrypted_buffer_size, unencrypted));
	wire_task* t = (wire_task*)unencrypted;
	//verify ID decodes correctly (so entire packet decodes)
	unsigned char target_ID[ID_size];
	crypto::id_from_pub(hosts[hostid].waiting_packet.dest_pub, target_ID);
	//fail_false(memcmp(target_ID, t->target_ID, ID_size)==0);
	bytes_to_hex_array(received_hex, t->target_ID, ID_size);
	bytes_to_hex_array(target_hex, target_ID, ID_size);
	bytes_to_hex_array(dest_addr, hosts[hostid].waiting_packet.dest_pub, ecc_pub_size);
	int paramlen = hosts[hostid].waiting_packet.contents_length-sizeof(wire_task);
	unsigned char* param = paramlen==0?nullptr:unencrypted+sizeof(wire_task);
	compute::copy_to_queue(dest_addr, hosts[hostid].waiting_packet.origin_pub,
	 	t->t.function_name, t->t.on_success, t->t.on_failure,param, paramlen);
	delete unencrypted;//TODO: fix failure memory leak (maybe create a goto)
	return true;
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
	//std::cerr<<"listening\n";
	while(1){
		//transmit comm queue
		while(1){
			auto c = comm_queue.acquire();
			//if there is nothing to transmit, release and quit
			if(c->size() == 0){
				comm_queue.release();
				break;
			}
			host_task* next = c->front();
			c->pop();
			comm_queue.release();
			if(!send_comm(next)){
				std::cerr<<"error sending comm\n";
				//TODO: decrement retry count, or schedule on_failure
				delete next;
			}
		}
		//poll for fresh incoming connections:
		pollfd listener_poll;
		listener_poll.fd = listener_no;
		listener_poll.events = POLLIN;
		listener_poll.revents = 0;
		poll(&listener_poll, hosts.size()+1, 0);
		//if there is an incoming connection...
		if(listener_poll.revents != 0){
			host con;
			socklen_t other_len = sizeof(sockaddr_in);
			//accept the connection
			int connection_no = accept(listener_no, (sockaddr*) &con.addr, &other_len);
			//if the connection is valid, add it to the list and reset its timeout
			if(connection_no >= 0){
				std::cerr<<"adding new connection\n";
				con.fd = connection_no;
				con.timeout = time(NULL) + con_timeout;
				hosts.push_back(con);
			}
		}
		//iterate over known connections
		for(int i = 0; i < hosts.size(); i++){
			//count waiting bytes
			int count;
			ioctl(hosts[i].fd, FIONREAD, &count);
			if(count > 0){
				//if no packet is currently waiting, and a header is in the pipe...
				if((!hosts[i].is_packet_waiting) && count >= sizeof(packet_header)){
					//read the header
					read(hosts[i].fd, &hosts[i].waiting_packet, sizeof(packet_header));
					//if the packet is too long, drop the connection
					if(hosts[i].waiting_packet.contents_length > max_packet_size){
						std::cerr<<"dropping (packet too long)\n";
						drop(i--);
						continue;
					}
					//if not, set packet is waiting and bump the timeout
					hosts[i].is_packet_waiting = true;
					std::cerr<<"extending (header)\n";
					hosts[i].timeout = time(NULL) + con_timeout;
				}
				//if a packet is waiting, and a body is in the pipe
				if(hosts[i].is_packet_waiting && count >= hosts[i].waiting_packet.contents_length){
					//std::cerr<<"receiving body\n";
					//read it off the pipe
					char* inbuf = new char[crypto::calc_encrypted_size(hosts[i].waiting_packet.contents_length)];
					read(hosts[i].fd, inbuf, crypto::calc_encrypted_size(hosts[i].waiting_packet.contents_length));
					if(!receive_body(i, (unsigned char*)inbuf)){
						std::cerr<<"receive failed\n";
						//TODO: generic failure?
					}
					delete inbuf;//TODO: do something with it
					hosts[i].is_packet_waiting = false;
					std::cerr<<"extending (body)\n";
					hosts[i].timeout = time(NULL) + con_timeout;
				}
			}
			//if connection has timed out, drop it
			if(hosts[i].timeout < time(NULL)){
				std::cerr<<"dropping (timeout)\n";
				drop(i--);
				continue;
			}
		}
	//std::cerr<<hosts.size()<<"\n";
	usleep(20000);
	}
}

void talk::add_to_comm_queue(host_task* t){
	comm_queue.acquire()->push(t);
	comm_queue.release();
}

void talk::init(int port){
	run_talk_worker(port);//TODO: threading
}