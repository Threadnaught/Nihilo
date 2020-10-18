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
		//std::cerr<<"writing to "<<key<<" with "<<datalen<<" bytes\n";
		fail_false(db->Put(writeOptions, key, leveldb::Slice((char*)data, datalen)).ok());
		return true;
	}

	void* read(const char* key, int* datalen){
		*datalen = 0;
		leveldb::ReadOptions readOptions;
		std::string out;
		//std::cerr<<"reading "<<key<<"\n";
		if(!db->Get(readOptions, key, &out).ok())
			return nullptr;
		*datalen = out.length();
		void* ret = new unsigned char[*datalen];
		memcpy(ret, out.c_str(), *datalen);
		return ret;
	}

	/*char* next(const char* prev_key){
		return nullptr;
	}*/
	bool delete_all_with_prefix(const char* prefix){
		leveldb::Iterator* it = db->NewIterator(leveldb::ReadOptions());
		for(it->Seek(prefix); it->Valid()&& it->key().starts_with(prefix); it->Next()){
			//std::cerr<<"current:"<<it->key().ToString()<<"\n";
			if(!db->Delete(leveldb::WriteOptions(), it->key()).ok())
				return false;
		}
		return true;
	}
	void acquire_lock(){
		database_mutex.lock();
	}
	void release_lock(){
		database_mutex.unlock();
	}
}