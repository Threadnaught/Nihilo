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

//TODO: crypto comparison
//origin and dest are not for the message
struct origin_dest{
	unsigned char this_pub[ecc_pub_size];
	unsigned char peer_pub[ecc_pub_size];
};

bool operator< (const origin_dest o1, const origin_dest o2){
	return memcmp(&o1, &o2, sizeof(origin_dest)) < 0;
}

struct network_session{
	bool session_finalized = false;
	time_t timeout;
	origin_dest pubs;
	unsigned char encryption_key[shared_secret_size];
	unsigned char peer_secret[aes_block_size];
	unsigned int peer_message_count = 0;
	unsigned char this_secret[aes_block_size];
	unsigned int this_message_count = 0;
	std::queue<host_task*> waiting_for_transmission; //stores tasks while connection is not finalised
	std::vector<host_task*> waiting_for_response;
	//INBOUND USES OURS, OUTBOUND USES THEIRS. THIS IS TO PREVENT MESSAGE DUPLICATION ATTACKS. 
	bool calc_hash(bool ours, unsigned char* hash_out){
		fail_false(crypto::sha256_n_bytes((ours) ? (this_secret) : (peer_secret), aes_block_size+sizeof(unsigned int), hash_out, aes_block_size));
		return true;
	}
};

enum preamble_type : unsigned char{
	create_session = 0,
	finalise_session = 1,
	session_task = 2,
	reset = 4 //TODO: replace with keepalive???
};

struct preamble{
	preamble_type type;
	unsigned short message_length;
};

struct host{
	int fd;
	sockaddr_in addr; 
	time_t timeout;
	bool empty = false;
	std::map<origin_dest, network_session*> sessions;
	std::map<std::array<unsigned char, aes_block_size>, origin_dest> next_inbound_session_hashes;
	bool is_preamble_waiting = false;
	preamble waiting_preamble;
};

std::vector<host> hosts;
thread::locker<std::queue<host_task*>> comm_queue;

int get_waiting(int fd){
	int count;
	ioctl(fd, FIONREAD, &count);
	return count;
}

//TODO: fail_goto for all these funcs

//this code assumes shared_secret_size mod aes_block_size is 0
//false from any of these functions should drop the whole connection immediatley
//IV is remote hash (ask me what that means)

//encrypt message for session and send to host
bool encrypt_and_send(host* h, network_session* s, void* to_send, int to_send_len, unsigned char* init_vector=nullptr){
	int enc_size = crypto::calc_encrypted_size(to_send_len);
	void* unencrypted_buf = malloc(enc_size-aes_block_size);
	memset(unencrypted_buf, 0, enc_size-aes_block_size);
	memcpy(unencrypted_buf, to_send, to_send_len);
	void* encrypted_buf = malloc(enc_size);
	if(init_vector != nullptr)
		memcpy(encrypted_buf, init_vector, aes_block_size);
	fail_false(crypto::encrypt(s->encryption_key, (unsigned char*)unencrypted_buf, to_send_len, (unsigned char*)encrypted_buf, init_vector != nullptr));
	write(h->fd, encrypted_buf, enc_size); //for some reason fail_false on this don't work?
	free(encrypted_buf);
	free(unencrypted_buf);
	return true;
}

bool send_task(host* h, network_session* s, host_task* t){
	//pre_pad_length is the length of all of the data that needs sending
	int pre_pad_length = sizeof(session_wire_task) + t->param_length /*pad goes here*/ + aes_block_size;
	//total_encrypted_length is the size of data on the wire
	int total_encrypted_length = crypto::calc_encrypted_size(pre_pad_length);
	//post pad length is pre_pad_length rounded up to the nearest block
	int post_pad_length = total_encrypted_length - aes_block_size;
	//decrypted stores the data to be sent
	unsigned char* decrypted = new unsigned char[post_pad_length];
	memset(decrypted, 0, post_pad_length);
	session_wire_task* swt = (session_wire_task*)decrypted;
	//peer secret is one of the checks that auths the message
	memcpy(swt->peer_secret, s->peer_secret, aes_block_size);
	swt->pad_bytes = post_pad_length - pre_pad_length;
	//TODO: change to new style
	memcpy(&swt->t, &t->t, sizeof(common_task));
	memcpy((swt+1), (t+1), t->param_length);
	unsigned char* pad_start = ((unsigned char*)(swt+1))+t->param_length;
	crypto::rng(nullptr, pad_start, swt->pad_bytes);
	unsigned char* checksum_start = pad_start + swt->pad_bytes;
	fail_false(crypto::sha256_n_bytes(decrypted, checksum_start-decrypted, checksum_start, aes_block_size));
	//the iv is the sha256(peer secret, message index)
	unsigned char iv[aes_block_size];
	fail_false(s->calc_hash(false, iv));
	s->peer_message_count++;
	//send the message:
	preamble p{
		.type = preamble_type::session_task,
		.message_length = (short unsigned int)total_encrypted_length
	};
	fail_false(write(h->fd, &p, sizeof(preamble)) == sizeof(preamble));
	fail_false(encrypt_and_send(h, s, decrypted, post_pad_length, iv));
	delete decrypted;
	return true;
}

bool send_waiting_tasks(host* h, network_session* ns){
	for(int i = 0; i < 5 && ns->waiting_for_transmission.size() > 0; i++){
		host_task* ht = ns->waiting_for_transmission.front();
		ns->waiting_for_transmission.pop();
		fail_false(send_task(h, ns, ht));
		delete ht;
	}
	return true;
}

//this function handles a preamble_type::session_task message
bool handle_session_task(host* h, void* message){
	//ensure this is a whole number of blocks
	fail_false(h->waiting_preamble.message_length % aes_block_size == 0);
	//search the iv/session hash for this session
	std::array<unsigned char, aes_block_size> searching_for;
	memcpy(searching_for.data(), message, aes_block_size);
	auto found = h->next_inbound_session_hashes.find(searching_for);
	fail_false(found != h->next_inbound_session_hashes.end());
	network_session* ns = h->sessions[found->second];
	//decrypt the value into a new buffer:
	int padded_decrypted_size = h->waiting_preamble.message_length-aes_block_size;
	unsigned char* decypted_padded = new unsigned char[padded_decrypted_size];
	fail_false(crypto::decrypt(ns->encryption_key, (unsigned char*)message, padded_decrypted_size, decypted_padded));
	session_wire_task* swt = (session_wire_task*)decypted_padded;
	//verify decrypted hash:
	unsigned char sha[aes_block_size];
	fail_false(crypto::sha256_n_bytes(decypted_padded, padded_decrypted_size - aes_block_size, sha, aes_block_size));
	fail_false(memcmp(sha, ((unsigned char*)decypted_padded)+(padded_decrypted_size - aes_block_size), aes_block_size) == 0);
	//verify peer_secret
	fail_false(memcmp(swt->peer_secret, ns->this_secret, aes_block_size) == 0);
	
	int param_length = padded_decrypted_size-sizeof(session_wire_task)-aes_block_size-(swt->pad_bytes & 0x0F);
	std::cerr<<"received task name:"<<swt->t.function_name<<"\n";
	
	char dest_addr[max_address_len];
	char orig_addr[max_address_len];
	dest_addr[0] = '~';
	bytes_to_hex(ns->pubs.this_pub,ecc_pub_size,dest_addr+1);
	inet_ntop(AF_INET, &h->addr, orig_addr, sizeof(orig_addr));
	strcpy(orig_addr+strlen(orig_addr), "~");
	bytes_to_hex(ns->pubs.peer_pub,ecc_pub_size,orig_addr+strlen(orig_addr));
	fail_false(compute::copy_to_queue(dest_addr, orig_addr, swt->t.function_name, swt->t.on_success, swt->t.on_failure, swt+1, param_length));
	
	//update inbound session hash index
	ns->this_message_count++;
	h->next_inbound_session_hashes.erase(found);
	std::array<unsigned char, aes_block_size> next;
	ns->calc_hash(true, next.data());
	h->next_inbound_session_hashes[next] = ns->pubs;
	delete decypted_padded;
	return true;
}

bool send_create_session(host* h, unsigned char* origin_pub, unsigned char* dest_pub, host_task* first_in_queue=nullptr){
	std::cerr<<"sending create\n";
	network_session* ns = new network_session();
	//get the encryption key for this session:
	unsigned char origin_priv[ecc_priv_size];
	fail_false(compute::get_priv(origin_pub, origin_priv));
	fail_false(crypto::derrive_shared(origin_priv, dest_pub, ns->encryption_key));
	//create and send the preamble
	preamble p {
		.type = preamble_type::create_session,
		.message_length=(short unsigned)(sizeof(origin_dest)+crypto::calc_encrypted_size(aes_block_size))
	};
	write(h->fd, &p, sizeof(preamble));
	//create and send the origin/dest for this session:
	memcpy(ns->pubs.this_pub, origin_pub, ecc_pub_size);
	memcpy(ns->pubs.peer_pub, dest_pub, ecc_pub_size);

	write(h->fd, &ns->pubs, sizeof(origin_dest));
	//create, encrypt and send this side's session secret
	crypto::rng(nullptr, ns->this_secret, aes_block_size);
	fail_false(encrypt_and_send(h, ns, ns->this_secret, aes_block_size));
	ns->timeout = time(NULL) + non_final_session_timeout;
	h->sessions[ns->pubs] = ns;
	if(first_in_queue != nullptr) 
		ns->waiting_for_transmission.push(first_in_queue);
	
	return true;
}
bool handle_create_session(host* h, void* message){
	std::cerr<<"handling create\n";
	fail_false(h->waiting_preamble.message_length == sizeof(origin_dest)+crypto::calc_encrypted_size(aes_block_size));
	network_session* ns = new network_session();
	origin_dest* inbound_origin_dest = (origin_dest*)message;
	//swap origin and dest around (our destination is the peer's origin)
	memcpy(ns->pubs.this_pub, inbound_origin_dest->peer_pub, sizeof(origin_dest));
	memcpy(ns->pubs.peer_pub, inbound_origin_dest->this_pub, sizeof(origin_dest));
	//derrive shared ecc key:
	unsigned char dest_priv[ecc_priv_size];
	fail_false(compute::get_priv(inbound_origin_dest->peer_pub, dest_priv));
	fail_false(crypto::derrive_shared(dest_priv, inbound_origin_dest->this_pub, ns->encryption_key));
	//get peer's secret:
	crypto::decrypt(ns->encryption_key, ((unsigned char*)message) + sizeof(origin_dest), aes_block_size, ns->peer_secret);
	//create our secret:
	crypto::rng(nullptr, ns->this_secret, aes_block_size);
	//construct and send response preamble:
	preamble p {
		.type = preamble_type::finalise_session,
		.message_length=(short unsigned)(sizeof(origin_dest)+crypto::calc_encrypted_size(aes_block_size*2))
	};
	write(h->fd, &p, sizeof(preamble));
	//send origin dest representing this session:
	write(h->fd, &ns->pubs, sizeof(origin_dest));
	//construct and encrypt secrets:
	unsigned char unencrypted_secrets[aes_block_size*2];
	unsigned char encrypted_secrets[crypto::calc_encrypted_size(aes_block_size*2)];
	//our secret is first to stop IV reuse
	memcpy(unencrypted_secrets, ns->this_secret, aes_block_size);
	memcpy(unencrypted_secrets+aes_block_size, ns->peer_secret, aes_block_size);
	fail_false(encrypt_and_send(h, ns, unencrypted_secrets, aes_block_size*2));
	//session is now final
	ns->timeout = time(NULL) + final_session_timeout;
	ns->session_finalized = true;
	//update session hash index
	std::array<unsigned char, aes_block_size> next_inbound_hash;
	ns->calc_hash(true, next_inbound_hash.data());
	h->next_inbound_session_hashes[next_inbound_hash] = ns->pubs;
	h->sessions[ns->pubs] = ns;
	return true;
}
bool handle_finalise_session(host* h, void* message){
	std::cerr<<"handling finalize\n";
	fail_false(h->waiting_preamble.message_length == sizeof(origin_dest)+crypto::calc_encrypted_size(aes_block_size*2));
	//create origin/dest to search for:
	origin_dest* inbound_origin_dest = (origin_dest*)message;
	//swap origin and dest around (our destination is the peer's origin)
	origin_dest search_target;
	memcpy(search_target.this_pub, inbound_origin_dest->peer_pub, sizeof(origin_dest));
	memcpy(search_target.peer_pub, inbound_origin_dest->this_pub, sizeof(origin_dest));
	auto it = h->sessions.find(search_target);
	fail_false(it != h->sessions.end());
	network_session* ns = it->second;
	unsigned char decrypted_secrets[aes_block_size*2];
	//first: verify our secret was parroted back to us:
	//ours is second because otherwise an attacker could forge a session (that they
	//couldn't use) by repeating our session create packet followed by 16 random bytes
	fail_false(crypto::decrypt(ns->encryption_key, ((unsigned char*)message) + sizeof(origin_dest), aes_block_size*2, decrypted_secrets));
	fail_false(memcmp(decrypted_secrets+aes_block_size, ns->this_secret, aes_block_size) == 0);
	memcpy(ns->peer_secret, decrypted_secrets, aes_block_size);
	ns->session_finalized = true;
	std::array<unsigned char, aes_block_size> next_inbound_hash;
	ns->calc_hash(true, next_inbound_hash.data());
	h->next_inbound_session_hashes[next_inbound_hash] = ns->pubs;
	ns->timeout = time(NULL) + final_session_timeout;
	//std::cerr<<"established!\n";
	return true;
}

//if false is returned, the connection should be dropped
bool handle_inbound(host* h){
	int count = get_waiting(h->fd);
	//if there are no packets, skip this host
	if(count == 0)
		return true;
	//if there isn't a preamble that's just been received, receive it and move on
	if(!h->is_preamble_waiting){
		if(count < sizeof(preamble))//if we have not yet received the whole preamble, continue to next host
			return true;
		h->is_preamble_waiting = true;
		fail_false(read(h->fd, &h->waiting_preamble, sizeof(preamble)) == sizeof(preamble));
		fail_false(h->waiting_preamble.message_length <= max_packet_size);//enforce reasonableness
		return true;
	}
	if(count < h->waiting_preamble.message_length)
		return true;//ditto with the message
	h->is_preamble_waiting = false;
	void* received_message = malloc(h->waiting_preamble.message_length);
	fail_false(read(h->fd, received_message, h->waiting_preamble.message_length) == h->waiting_preamble.message_length);
	bool ret = false;
	switch (h->waiting_preamble.type){//speaks for itself, really
		case preamble_type::create_session:
			ret = handle_create_session(h, received_message);
			break;
		case preamble_type::finalise_session:
			ret = handle_finalise_session(h, received_message);
			break;
		case preamble_type::session_task:
			ret = handle_session_task(h, received_message);
			break;
		default:
			std::cerr<<"unrecognised preamble type:"<<h->waiting_preamble.type<<"\n";
			ret = false;
	}
	free(received_message);
	fail_false(ret);
	return true;
}
bool handle_host(host* h){
	fail_false(handle_inbound(h));
	std::vector<origin_dest> to_drop;//not really sure why this hack is needed but fuck if it doesn't break without it
	for(auto it = h->sessions.begin(); it != h->sessions.end(); it++){
		if(it->second->session_finalized){
			fail_false(send_waiting_tasks(h, it->second));
		}
		if(time(NULL) > it->second->timeout){
			std::cerr<<"dropping session (timeout)\n";
			to_drop.push_back(it->first);
		}
		
	}
	for(int i = 0; i < to_drop.size(); i++){
		std::array<unsigned char, aes_block_size> inbound_delete;
		h->sessions[to_drop[i]]->calc_hash(true, inbound_delete.data());
		h->next_inbound_session_hashes.erase(inbound_delete);
		h->sessions.erase(to_drop[i]);
	}
	//manage whole-host timeout:
	if(h->sessions.size() == 0 && !h->empty){
		h->timeout = time(NULL) + empty_host_timeout;
		h->empty = true;
	} else if (h->sessions.size() > 0 && h->empty){
		h->empty = false;
	}
	if (h->empty && h->timeout < time(NULL)){
		std::cerr<<"dropping connection\n";
		return false;
	}
	return true;
}

void drop(int con_no){
	shutdown(hosts[con_no].fd, SHUT_RDWR);
	close(hosts[con_no].fd);
	//TODO: schedule failures
	hosts.erase(hosts.begin() + con_no);
}

bool queue_comm_to_session(host_task* ht){
	char receiver_hostname[max_address_len];
	fail_false(compute::get_address_ip_target(ht->dest_addr, receiver_hostname));
	char receiver_identifier[max_address_len];
	fail_false(compute::get_address_machine_target(ht->dest_addr, receiver_identifier));
	char sender_identifier[max_address_len];
	fail_false(compute::get_address_machine_target(ht->origin_addr, sender_identifier));
	if(receiver_identifier[0] != '~'){
		std::cerr<<"Network RPC must specify target pub\n"; //this will need dnssec or simiilar to solve
		fail_false(false);
	}
	int found_host = -1;
	sockaddr_in search_address;
	hostent* target_ent = gethostbyname(receiver_hostname);
	fail_false(target_ent != nullptr);
	memset(&search_address, 0, sizeof(search_address));
	search_address.sin_family = AF_INET;
	memcpy(&search_address.sin_addr.s_addr, target_ent->h_addr_list[0], target_ent->h_length);
	search_address.sin_port = htons(tcp_port);
	//check for already established connection:
	char tgt_addr[20];
	inet_ntop(AF_INET, &search_address, tgt_addr, sizeof(tgt_addr));
	int host_index = -1;
	for(int i = 0; i < hosts.size(); i++){//TODO: optimise
		char this_addr[20];
		inet_ntop(AF_INET, &hosts[i].addr, this_addr, sizeof(this_addr));
		if((strcmp(this_addr, receiver_hostname)==0) || (search_address.sin_addr.s_addr == hosts[i].addr.sin_addr.s_addr)){
			std::cerr<<"found\n";
			host_index = i;
			break;
		}
	}
	//if there is no already established connection, connect
	if(host_index == -1){
		host fresh_con;
		//open socket:
		fresh_con.fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
		fail_false(fresh_con.fd >= 0);
		fail_false(connect(fresh_con.fd, (sockaddr*)&search_address, sizeof(sockaddr_in)) >= 0);
		fresh_con.addr = search_address;
		hosts.push_back(fresh_con);
		host_index = hosts.size() - 1;
		std::cerr<<"established\n";
	}
	origin_dest pubs;
	fail_false(compute::resolve_local_machine(sender_identifier, pubs.this_pub));
	
	hex_to_bytes(receiver_identifier+1, pubs.peer_pub);//todo: hex_to_bytes specific length
	auto it = hosts[host_index].sessions.find(pubs);
	if(it != hosts[host_index].sessions.end()){
		it->second->waiting_for_transmission.push(ht);
	} else {
		send_create_session(&hosts[host_index], pubs.this_pub, pubs.peer_pub, ht);
	}
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
	fail_false(listen(listener_no,5) == 0);
	//std::cerr<<"listening\n";
	while(1){
		//apply comm queue to relevant sessions:
		while(1){
			auto c = comm_queue.acquire();
			if(c->size() == 0){
				comm_queue.release();
				break;
			}
			host_task* next = c->front();
			c->pop();
			comm_queue.release();
			char ip_target[max_address_len];
			fail_false(compute::get_address_ip_target(next->dest_addr, ip_target));
			fail_false(queue_comm_to_session(next));
		}
		//poll for fresh incoming connections:
		pollfd listener_poll;
		listener_poll.fd = listener_no;
		listener_poll.events = POLLIN;
		listener_poll.revents = 0;
		poll(&listener_poll, 1, 0);
		if(listener_poll.revents != 0){
			host con;
			socklen_t other_len = sizeof(sockaddr_in);
			//accept the connection
			int connection_no = accept(listener_no, (sockaddr*) &con.addr, &other_len);
			//if the connection is valid, add it to the list and reset its timeout
			if(connection_no >= 0){
				//std::cerr<<"adding new connection\n";
				con.fd = connection_no;
				hosts.push_back(con);
			}
		}
		//iterate over known connections
		for(int i = 0; i < hosts.size(); i++){
			if(!handle_host(&hosts[i])){
				drop(i--);
			}
		}
		usleep(10000);
	}
}

void talk::add_to_comm_queue(host_task* t){
	comm_queue.acquire()->push(t);
	comm_queue.release();
}

void talk::init(int port){
	run_talk_worker(port);
}