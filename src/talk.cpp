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
//TODO: allow for multiple sessions between the same origin and dest (fork session)???????????????
//TODO: crypto comparison
//origin and dest are not for the message
struct origin_dest{
	unsigned char origin_pub[ecc_pub_size];
	unsigned char dest_pub[ecc_pub_size];
};

bool operator< (const origin_dest o1, const origin_dest o2){
	return memcmp(&o1, &o2, sizeof(origin_dest)) < 0;
}
struct network_session{//TODO:create generic session for intra-host queues
	bool session_finalized = false;
	time_t timeout;
	origin_dest pubs;
	unsigned char encryption_key[shared_secret_size];
	unsigned char peer_secret[session_secret_size];
	unsigned int peer_message_count = 0;
	unsigned char this_secret[session_secret_size];
	unsigned int this_message_count = 0;
	std::queue<host_task*> waiting_for_transmission; //stores tasks while connection is not finalised
	std::vector<host_task*> waiting_for_response;
	//INBOUND USES OURS, OUTBOUND USES THEIRS. THIS IS TO PREVENT MESSAGE DUPLICATION ATTACKS. 
	bool calc_hash(bool ours, unsigned char* hash_out){
		fail_false(crypto::sha256_n_bytes((ours) ? (this_secret) : (peer_secret), shared_secret_size+sizeof(unsigned int), hash_out, shared_secret_size));
		return true;
	}
};

enum preamble_type : unsigned char{
	create_session = 0,
	finalise_session = 1,
	session_task = 2,
	reset = 4 //TODO
};

struct preamble{
	preamble_type type;
	unsigned short message_length;
};

struct host{
	int fd;
	sockaddr_in addr; 
	time_t timeout;
	bool is_packet_waiting;
	packet_header waiting_packet;

	std::map<origin_dest, network_session*> sessions;
	std::map<std::array<unsigned char, session_secret_size>, origin_dest> next_inbound_session_hashes;
	bool is_preamble_waiting = false;
	preamble waiting_preamble;
};


int get_waiting(int fd){
	int count;
	ioctl(fd, FIONREAD, &count);
	return count;
}

//TODO: fail_goto for all these funcs

//TODO: this code assumes shared_secret_size mod aes_block_size is 0

//false from any of these functions should drop the whole connection immediatley

//IV is remote hash (ask me what that means)

bool encrypt_and_send(host* h, network_session* s, void* to_send, int to_send_len, unsigned char* init_vector=nullptr){
	int enc_size = crypto::calc_encrypted_size(to_send_len);
	void* unencrypted_buf = malloc(enc_size-aes_block_size);
	memset(unencrypted_buf, 0, enc_size-aes_block_size);
	memcpy(unencrypted_buf, to_send, to_send_len);
	void* encrypted_buf = malloc(enc_size);
	if(init_vector != nullptr)
		memcpy(encrypted_buf, init_vector, aes_block_size);
	fail_false(crypto::encrypt(s->encryption_key, (unsigned char*)unencrypted_buf, to_send_len, (unsigned char*)encrypted_buf, init_vector != nullptr));
	write(h->fd, encrypted_buf, enc_size);
	free(encrypted_buf);
	free(unencrypted_buf);
	return true;
}

bool send_task(host* h, network_session* s, host_task* t){
	//TEMP
	int pre_pad_length = sizeof(session_wire_task) + t->param_length /*pad goes here*/ + aes_block_size;
	int total_encrypted_length = crypto::calc_encrypted_size(pre_pad_length);
	int post_pad_length = total_encrypted_length - aes_block_size;
	unsigned char* decrypted = new unsigned char[post_pad_length];
	memset(decrypted, 0, post_pad_length);
	session_wire_task* swt = (session_wire_task*)decrypted;
	memcpy(swt->peer_secret, s->peer_secret, session_secret_size);
	swt->length_anomaly = post_pad_length - pre_pad_length;
	memcpy(&swt->t, &t->t, sizeof(common_task));
	memcpy((swt+1), (t+1), t->param_length);
	unsigned char* pad_start = ((unsigned char*)(swt+1))+t->param_length;
	crypto::rng(nullptr, pad_start, swt->length_anomaly);
	unsigned char* checksum_start = pad_start + swt->length_anomaly;
	fail_false(crypto::sha256_n_bytes(decrypted, checksum_start-decrypted, checksum_start, aes_block_size));
	unsigned char iv[session_secret_size];
	fail_false(s->calc_hash(false, iv));
	s->peer_message_count++;
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

bool handle_session_task(host* h, void* message){
	//TODO: fail false too short
	fail_false(h->waiting_preamble.message_length % aes_block_size == 0);
	std::array<unsigned char, session_secret_size> searching_for;
	memcpy(searching_for.data(), message, session_secret_size);
	auto found = h->next_inbound_session_hashes.find(searching_for);//TODO: eval whether this is vulnerable to a timing attack?? (wait for 500ms to send negative response??)
	fail_false(found != h->next_inbound_session_hashes.end());//TODO: see above
	network_session* ns = h->sessions[found->second];
	int padded_decrypted_size = h->waiting_preamble.message_length-aes_block_size;
	unsigned char* decypted_padded = new unsigned char[padded_decrypted_size];
	fail_false(crypto::decrypt(ns->encryption_key, (unsigned char*)message, padded_decrypted_size, decypted_padded));
	session_wire_task* swt = (session_wire_task*)decypted_padded;
	unsigned char sha[aes_block_size];
	char hashed_padded_decrypted_TEMP[5000];
	bytes_to_hex(decypted_padded, padded_decrypted_size - aes_block_size, hashed_padded_decrypted_TEMP);
	fail_false(crypto::sha256_n_bytes(decypted_padded, padded_decrypted_size - aes_block_size, sha, aes_block_size));
	fail_false(memcmp(sha, ((unsigned char*)decypted_padded)+(padded_decrypted_size - aes_block_size), aes_block_size) == 0);//TODO: see above
	fail_false(memcmp(swt->peer_secret, ns->this_secret, session_secret_size) == 0);//TODO: see above
	int param_length = padded_decrypted_size-sizeof(session_wire_task)-aes_block_size-(swt->length_anomaly & 0x0F);
	
	std::cerr<<"received task name:"<<swt->t.function_name<<"\n";

	ns->this_message_count++;
	h->next_inbound_session_hashes.erase(found);
	std::array<unsigned char, session_secret_size> next;
	ns->calc_hash(true, next.data());
	h->next_inbound_session_hashes[next] = ns->pubs;

	return true;
}

bool send_create_session(host* h, unsigned char* origin_pub, unsigned char* dest_pub){
	std::cerr<<"sending create\n";
	network_session* ns = new network_session();
	//get the encryption key for this session:
	unsigned char origin_priv[ecc_priv_size];
	fail_false(compute::get_priv(origin_pub, origin_priv));
	fail_false(crypto::derrive_shared(origin_priv, dest_pub, ns->encryption_key));
	//create and send the preamble
	preamble p {
		.type = preamble_type::create_session,
		.message_length=(short unsigned)(sizeof(origin_dest)+crypto::calc_encrypted_size(session_secret_size))
	};
	write(h->fd, &p, sizeof(preamble));
	//create and send the origin/dest for this session:
	memcpy(ns->pubs.origin_pub, origin_pub, ecc_pub_size);
	memcpy(ns->pubs.dest_pub, dest_pub, ecc_pub_size);
	write(h->fd, &ns->pubs, sizeof(origin_dest));
	//create, encrypt and send this side's session secret
	crypto::rng(nullptr, ns->this_secret, session_secret_size);
	fail_false(encrypt_and_send(h, ns, ns->this_secret, session_secret_size));
	//TODO: timeout (short)
	h->sessions[ns->pubs] = ns;
	//TEMP
	host_task* ht = new host_task();
	ht->param_length = 0;
	strcpy(ht->t.function_name, "shit");
	ns->waiting_for_transmission.emplace(ht);
	ht = new host_task();
	ht->param_length = 0;
	strcpy(ht->t.function_name, "son");
	ns->waiting_for_transmission.emplace(ht);
	///TEMP
	return true;
}
bool handle_create_session(host* h, void* message){
	std::cerr<<"handling create\n";
	fail_false(h->waiting_preamble.message_length == sizeof(origin_dest)+crypto::calc_encrypted_size(session_secret_size));
	network_session* ns = new network_session();
	origin_dest* inbound_origin_dest = (origin_dest*)message;
	//swap origin and dest around (our destination is the peer's origin)
	memcpy(ns->pubs.origin_pub, inbound_origin_dest->dest_pub, sizeof(origin_dest));
	memcpy(ns->pubs.dest_pub, inbound_origin_dest->origin_pub, sizeof(origin_dest));
	//derrive shared ecc key:
	unsigned char dest_priv[ecc_priv_size];
	fail_false(compute::get_priv(inbound_origin_dest->dest_pub, dest_priv));
	fail_false(crypto::derrive_shared(dest_priv, inbound_origin_dest->origin_pub, ns->encryption_key));
	//get peer's secret:
	crypto::decrypt(ns->encryption_key, ((unsigned char*)message) + sizeof(origin_dest), session_secret_size, ns->peer_secret);
	//create our secret:
	crypto::rng(nullptr, ns->this_secret, session_secret_size);
	//construct and send response preamble:
	preamble p {
		.type = preamble_type::finalise_session,
		.message_length=(short unsigned)(sizeof(origin_dest)+crypto::calc_encrypted_size(session_secret_size*2))
	};
	write(h->fd, &p, sizeof(preamble));
	//send origin dest representing this session:
	write(h->fd, &ns->pubs, sizeof(origin_dest));
	//construct and encrypt secrets:
	unsigned char unencrypted_secrets[session_secret_size*2];
	unsigned char encrypted_secrets[crypto::calc_encrypted_size(session_secret_size*2)];
	memcpy(unencrypted_secrets, ns->this_secret, session_secret_size);
	memcpy(unencrypted_secrets+session_secret_size, ns->peer_secret, session_secret_size);
	fail_false(crypto::encrypt(ns->encryption_key, unencrypted_secrets, session_secret_size*2, encrypted_secrets));
	write(h->fd, encrypted_secrets, crypto::calc_encrypted_size(session_secret_size*2));
	//TODO: timeout (short)
	ns->session_finalized = true;
	std::array<unsigned char, session_secret_size> next_inbound_hash;
	ns->calc_hash(true, next_inbound_hash.data());
	h->next_inbound_session_hashes[next_inbound_hash] = ns->pubs;
	h->sessions[ns->pubs] = ns;
	//TEMP
	host_task* ht = new host_task();
	ht->param_length = 0;
	strcpy(ht->t.function_name, "no");
	ns->waiting_for_transmission.emplace(ht);

	ht = new host_task();
	ht->param_length = 0;
	strcpy(ht->t.function_name, "yes");
	ns->waiting_for_transmission.emplace(ht);
	///TEMP
	fail_false(send_waiting_tasks(h, ns));
	return true;
}
bool handle_finalise_session(host* h, void* message){
	std::cerr<<"handling finalize\n";
	fail_false(h->waiting_preamble.message_length == sizeof(origin_dest)+crypto::calc_encrypted_size(session_secret_size*2));
	//create origin/dest to search for:
	origin_dest* inbound_origin_dest = (origin_dest*)message;
	//swap origin and dest around (our destination is the peer's origin)
	origin_dest search_target;
	memcpy(search_target.origin_pub, inbound_origin_dest->dest_pub, sizeof(origin_dest));
	memcpy(search_target.dest_pub, inbound_origin_dest->origin_pub, sizeof(origin_dest));
	//TODO: index this linear search
	auto it = h->sessions.find(search_target);
	fail_false(it != h->sessions.end());
	network_session* ns = it->second;
	unsigned char decrypted_secrets[shared_secret_size*2];
	//first: verify our secret was parroted back to us:
	//ours is second because otherwise an attacker could forge a session (that they
	//couldn't use) by repeating our session create packet followed by 16 random bytes
	fail_false(crypto::decrypt(ns->encryption_key, ((unsigned char*)message) + sizeof(origin_dest), shared_secret_size*2, decrypted_secrets));
	fail_false(memcmp(decrypted_secrets+shared_secret_size, ns->this_secret, shared_secret_size) == 0);
	memcpy(ns->peer_secret, decrypted_secrets, shared_secret_size);
	ns->session_finalized = true;
	std::array<unsigned char, session_secret_size> next_inbound_hash;
	ns->calc_hash(true, next_inbound_hash.data());
	h->next_inbound_session_hashes[next_inbound_hash] = ns->pubs;
	//TODO: timeout (short)
	std::cerr<<"established!\n";
	fail_false(send_waiting_tasks(h, ns));
	return true;
}

//if false is returned, the connection should be dropped
bool handle_host(host* h){
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

std::vector<host> hosts;

//THREAD UNSAFE, ONLY TO BE CALLED FROM THE TALK WORKER THREAD
bool send_comm(host_task* t){
	unsigned char* unencrypted = nullptr;
	unsigned char* encrypted = nullptr;
	wire_task* wire = nullptr;
	int encrypted_buffer_size = 0;
	int unencrypted_buffer_size = 0;
	hostent* target_ent = nullptr;
	host fresh_con;
	int host_index = -1;
	char receiver_hostname[max_address_len];
	fail_false(compute::get_address_ip_target(t->dest_addr, receiver_hostname));
	char receiver_identifier[max_address_len];
	fail_false(compute::get_address_machine_target(t->dest_addr, receiver_identifier));
	char sender_identifier[max_address_len];
	fail_false(compute::get_address_machine_target(t->origin_addr, sender_identifier));
	//open socket:
	int connection_no = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	fail_goto(connection_no >= 0);
	//DNS/IP lookup:
	target_ent = gethostbyname(receiver_hostname);
	fail_goto(target_ent != nullptr);
	//fresh_con ONLY USEFUL FOR A FRESH CONNECTION, USE host_index FOR EITHER A FOUND OR FRESH CONNECTION
	memset(&fresh_con.addr, 0, sizeof(sockaddr_in));
	fresh_con.addr.sin_family = AF_INET;
	memcpy(&fresh_con.addr.sin_addr.s_addr, target_ent->h_addr_list[0], target_ent->h_length);
	fresh_con.addr.sin_port = htons(tcp_port);
	//check for already established connection:
	char tgt_addr[20];
	inet_ntop(AF_INET, &fresh_con.addr, tgt_addr, 15);
	for(int i = 0; i < hosts.size(); i++){
		char this_addr[20];
		inet_ntop(AF_INET, &hosts[i].addr, this_addr, 20);
		if((strcmp(this_addr, receiver_hostname)==0) || (fresh_con.addr.sin_addr.s_addr == hosts[i].addr.sin_addr.s_addr)){
			//std::cerr<<"found!\n";
			host_index = i;
			break;
		}
	}
	//if there is no already established connection, connect
	if(host_index == -1){
		fail_goto(connect(connection_no, (sockaddr*)&fresh_con.addr, sizeof(sockaddr_in)) >= 0);
		fresh_con.fd = connection_no;
		hosts.push_back(fresh_con);
		host_index = hosts.size() - 1;
		//std::cerr<<"established!\n";
	}
	//reset timeout:
	hosts[host_index].timeout = time(NULL) + con_timeout;
	//derrive shared secret:
	if(receiver_identifier[0] != '~'){
		std::cerr<<"destination pubkey must currently be specified\n"; //(TODO)
		fail_false(false);
	}
	hex_to_bytes_array(receiver_pub, receiver_identifier+1, ecc_pub_size);
	unsigned char origin_pub[ecc_pub_size];
	fail_false(compute::resolve_local_machine(t->origin_addr, origin_pub));
	unsigned char send_priv[ecc_priv_size];
	fail_goto(compute::get_priv(origin_pub, send_priv));
	unsigned char secret[shared_secret_size];
	fail_goto(crypto::derrive_shared(send_priv, receiver_pub, secret));
	//construct and send header:
	packet_header header;
	memcpy(header.origin_pub, origin_pub, ecc_pub_size);
	memcpy(header.dest_pub, receiver_pub, ecc_pub_size);
	header.contents_length = sizeof(wire_task) + t->param_length;
	fail_goto(write(hosts[host_index].fd, (void*)&header, sizeof(packet_header)) >= 0);
	//std::cerr<<"wrote header\n";
	//construct body:
	encrypted_buffer_size = crypto::calc_encrypted_size(header.contents_length);
	//rounded to the nearest block, but without IV
	unencrypted_buffer_size = encrypted_buffer_size - aes_block_size;
	unencrypted = new unsigned char[unencrypted_buffer_size];
	//don't want to expose memory to peer
	memset(unencrypted, 0, unencrypted_buffer_size);
	wire = (wire_task*)unencrypted;
	//copy over target id/task info/param
	memcpy(wire->target_pub, header.dest_pub, ecc_pub_size);
	memcpy(&wire->t, &t->t, sizeof(common_task));
	if(t->param_length > 0)
		memcpy(unencrypted+sizeof(wire_task), ((char*)t)+sizeof(host_task), t->param_length);
	//encrypt and send body:
	encrypted = new unsigned char[encrypted_buffer_size];
	fail_goto(crypto::encrypt(secret, unencrypted, unencrypted_buffer_size, encrypted));
	fail_goto(write(hosts[host_index].fd, encrypted, encrypted_buffer_size) >= 0);
	//memory cleanup:
	delete encrypted;
	delete unencrypted;
	delete t;
	return true;
	fail:
	if(encrypted != nullptr)
		delete encrypted;
	if(unencrypted != nullptr)
		delete unencrypted;
	delete t;
	return false;
}

void drop(int con_no){
	shutdown(hosts[con_no].fd, SHUT_RDWR);
	close(hosts[con_no].fd);
	hosts.erase(hosts.begin() + con_no);
}

bool receive_body(int hostid, unsigned char* body){
	//std::cerr<<"receiving body\n";
	unsigned char dest_priv[ecc_priv_size];
	int encrypted_buffer_size;
	int unencrypted_buffer_size;
	unsigned char* unencrypted = nullptr;
	wire_task* t;
	int paramlen;
	unsigned char* param;
	fail_goto(compute::get_priv(hosts[hostid].waiting_packet.dest_pub, dest_priv));
	unsigned char secret[shared_secret_size];
	crypto::derrive_shared(dest_priv, hosts[hostid].waiting_packet.origin_pub, secret);
	encrypted_buffer_size = crypto::calc_encrypted_size(hosts[hostid].waiting_packet.contents_length);
	//rounded to the nearest block, but without IV
	unencrypted_buffer_size = encrypted_buffer_size - aes_block_size;
	unencrypted = new unsigned char[unencrypted_buffer_size];
	fail_goto(crypto::decrypt(secret, body, unencrypted_buffer_size, unencrypted));
	t = (wire_task*)unencrypted;
	fail_goto(memcmp(t->target_pub, hosts[hostid].waiting_packet.dest_pub, ecc_pub_size)==0);
	//construct request on this side
	char dest_addr[max_address_len];
	dest_addr[0] = '~';
	bytes_to_hex(hosts[hostid].waiting_packet.dest_pub, ecc_pub_size, dest_addr+1);
	//if there is a parameter, attach it to the task
	paramlen = hosts[hostid].waiting_packet.contents_length-sizeof(wire_task);
	param = paramlen==0?nullptr:unencrypted+sizeof(wire_task);
	char origin_addr[max_address_len];
	inet_ntop(AF_INET, &hosts[hostid].addr, origin_addr, 15);
	origin_addr[strlen(origin_addr)+1] = '\0';
	origin_addr[strlen(origin_addr)] = '~';
	bytes_to_hex(hosts[hostid].waiting_packet.origin_pub, ecc_pub_size, origin_addr + strlen(origin_addr));
	compute::copy_to_queue(dest_addr, origin_addr, t->t.function_name, t->t.on_success, t->t.on_failure,param, paramlen);
	delete unencrypted;
	return true;
	fail:
	if(unencrypted != nullptr)
		delete unencrypted;
	return false;
}

bool run_talk_worker(int port){
	//TODO: remove
	bool TEMP_PING = port == 0;
	port = tcp_port;


	

	host fresh_con;

	if(TEMP_PING){
		host h;
		//open socket:
		int connection_no = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
		fail_false(connection_no >= 0);
		//DNS/IP lookup:
		hostent* target_ent = gethostbyname("nihilo_host");
		fail_false(target_ent != nullptr);
		
		memset(&fresh_con.addr, 0, sizeof(sockaddr_in));
		fresh_con.addr.sin_family = AF_INET;
		memcpy(&fresh_con.addr.sin_addr.s_addr, target_ent->h_addr_list[0], target_ent->h_length);
		fresh_con.addr.sin_port = htons(tcp_port);
		fail_false(connect(connection_no, (sockaddr*)&fresh_con.addr, sizeof(sockaddr_in)) >= 0);
		fresh_con.fd = connection_no;
		hex_to_bytes_array(dest, "24DF0DBA4734475616B1B19E3DD82093FE7A7A7187CDE2ACD4A12386B60DE2BC", ecc_pub_size);//TODO
		unsigned char orig[ecc_pub_size];
		compute::resolve_local_machine("#root", orig);
		send_create_session(&fresh_con, orig, dest);
	} else {
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
		pollfd listener_poll;
		listener_poll.fd = listener_no;
		listener_poll.events = POLLIN;
		listener_poll.revents = 0;
		while(poll(&listener_poll, 1, 0) < 0);
		socklen_t other_len = sizeof(sockaddr_in);
		fresh_con.fd = accept(listener_no, (sockaddr*) &fresh_con.addr, &other_len);
	}

	while(handle_host(&fresh_con)){
		usleep(100);
	}

	return true;
}
bool run_talk_worker_old(int port){
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
				if(next->retry_count++ < max_retries){
					c = comm_queue.acquire();
					c->push(next);
					comm_queue.release();
				}
				else
					delete next;
			}
		}
		//poll for fresh incoming connections:
		pollfd listener_poll;
		listener_poll.fd = listener_no;
		listener_poll.events = POLLIN;
		listener_poll.revents = 0;
		poll(&listener_poll, hosts.size()+1, 0);//TODO: this looks like a bug?
		//if there is an incoming connection...
		if(listener_poll.revents != 0){
			host con;
			socklen_t other_len = sizeof(sockaddr_in);
			//accept the connection
			int connection_no = accept(listener_no, (sockaddr*) &con.addr, &other_len);
			//if the connection is valid, add it to the list and reset its timeout
			if(connection_no >= 0){
				//std::cerr<<"adding new connection\n";
				con.fd = connection_no;
				con.timeout = time(NULL) + con_timeout;
				hosts.push_back(con);
			}
		}
		//iterate over known connections
		for(int i = 0; i < hosts.size(); i++){
			//count waiting bytes
			int count;
			if((count = get_waiting(hosts[i].fd)) > 0){
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
					//std::cerr<<"extending (header)\n";
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
						drop(i--);
						continue;
					}
					delete inbuf;
					hosts[i].is_packet_waiting = false;
					//std::cerr<<"extending (body)\n";
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