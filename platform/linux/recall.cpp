#include"../../include/platform.h"

#include<leveldb/db.h>

leveldb::DB* db;
std::mutex database_mutex;

namespace recall{
	bool init(const char* dbpath){
		leveldb::Options options;
		options.create_if_missing = true;
		fail_false(leveldb::DB::Open(options, dbpath, &db).ok());
		return true;
	}

	bool write(const char* key, const void* data, int datalen){
		leveldb::WriteOptions writeOptions;
		fail_false(db->Put(writeOptions, key, leveldb::Slice((char*)data, datalen)).ok());
		return true;
	}

	void* read(const char* key, int* datalen){
		*datalen = 0;
		leveldb::ReadOptions readOptions;
		std::string out;
		if(!db->Get(readOptions, key, &out).ok())
			return nullptr;
		*datalen = out.length();
		unsigned char* ret = new unsigned char[*datalen];
		memcpy(ret, out.c_str(), *datalen);
		return ret;
	}

	char* next(const char* prev_key){
		return nullptr;
	}
	void acquire_lock(){
		database_mutex.lock();
	}
	void release_lock(){
		database_mutex.unlock();
	}
}