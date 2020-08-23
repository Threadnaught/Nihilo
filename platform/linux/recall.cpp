#include"../../include/platform.h"

#include<leveldb/db.h>

leveldb::DB* db;

namespace recall{
	bool init(const char* dbpath){
		leveldb::Options options;
		options.create_if_missing = true;
		fail_false(leveldb::DB::Open(options, "/tmp/whatever", &db).ok());
		return true;
	}

	bool write(const char* key, const unsigned char* data, int datalen){
		leveldb::WriteOptions writeOptions;
		fail_false(db->Put(writeOptions, key, leveldb::Slice((char*)data, datalen)).ok());
		return true;
	}

	unsigned char* read(const char* key, int* datalen){
		leveldb::ReadOptions readOptions;
		std::string out;
		fail_check(db->Get(readOptions, key, &out).ok(), nullptr);
		*datalen = out.length();
		unsigned char* ret = new unsigned char[*datalen];
		memcpy(ret, out.c_str(), *datalen);
		return ret;
	}

	char* next(const char* prev_key){
		return nullptr;
	}
}