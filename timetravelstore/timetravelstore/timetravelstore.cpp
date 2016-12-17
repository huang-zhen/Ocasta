// timetravelstore.cpp

#include <string>
#include <memory.h>
#include <assert.h>
#include "../../libhiredis/hiredis.h"
#include "timetravelstore.h"
using namespace std;


struct TimeTravelStore::handle {
	int hasupdate;
	int db;
	redisContext *context;
};

TimeTravelStore::TimeTravelStore()
{
	connection = NULL;
#ifdef WIN32
	InitializeCriticalSection(&sect);
#else
	mutex = 0;
#endif
}

TimeTravelStore::~TimeTravelStore()
{
	if (connection) {
		if (connection->hasupdate)
			flush();
		redisFree(connection->context);
		delete connection;
	}
#ifdef WIN32
	DeleteCriticalSection(&sect);
#endif
}

void TimeTravelStore::lock()
{
#ifdef WIN32
	EnterCriticalSection(&sect);
#else
	tas_mutex_lock(&mutex);
#endif

}

void TimeTravelStore::unlock()
{
#ifdef WIN32
	LeaveCriticalSection(&sect);
#else
	tas_mutex_unlock(&mutex);
#endif
}

int TimeTravelStore::init(const char *server)
{
	int ret = -1;

	lock();
	if (!connection) {
		connection = new handle();
		if (connection) {
			connection->hasupdate = 0;
			connection->db = 0;
			connection->context = redisConnect(server, 6379);
			if (!connection->context->err) {
				ret = 0;
			}
		}
	}
	unlock();
	return ret;
}

int TimeTravelStore::selectdb(int db)
{
    redisReply *reply = NULL;
	int ret = -1;

	if (db >= 0) {
		reply = (redisReply*)redisCommand(connection->context,"SELECT %d", db);
		if (reply && reply->type == 5 && reply->integer == 0) {
			connection->db = db;
			ret = 0;
		}
	}
	return ret;
}

int TimeTravelStore::create_key_ex(const char *key, double timestamp, int flag)
{
	int ret = -1;
	lock();
	ret = create_key(key, timestamp, flag);
	unlock();
	return ret;
}

int TimeTravelStore::create_key(const char *key, double timestamp, int flag)
{
    redisReply *reply = NULL;
	int ret = -1;

	key_info_t key_info;
	connection->hasupdate = 1;
	memset(&key_info, 0, sizeof(key_info));
	key_info.create_time = timestamp;
	key_info.create_count = 1;
	reply = (redisReply*)redisCommand(connection->context,"LLEN %s", key);
	if (reply) {
		if (reply->type == 3) {
			if (reply->integer == 0) {
				reply = (redisReply*)redisCommand(connection->context,"RPUSH %s %b", key, (char *)&key_info, sizeof(key_info));
				if (reply)
					ret = 0;
			} else {
				if (!flag) {
					if (!get_key_info(key, &key_info)) {
						key_info.last_create_time = timestamp;
						key_info.create_count ++;
						if (!set_key_info(key, &key_info))
							ret = 0;
					}
				}
			}
		}
		//else
		//	reply = (redisReply*)redisCommand(connection->context,"LSET %s 0 %b", key, (char *)&key_info, sizeof(key_info));
		freeReplyObject(reply);
	}
	return ret;
}

int TimeTravelStore::delete_key(const char *key, double timestamp, int flag)
{
    redisReply *reply = NULL;
	int ret = -1;

	lock();
	key_info_t key_info;
	connection->hasupdate = 1;
	if (!flag) {
		if (!get_key_info(key, &key_info)) {
			int type = -1;
			int len = sizeof(type) + sizeof(timestamp);
			char *buf = new char[len];
			if (buf) {
				memcpy(buf, &type, sizeof(type));
				memcpy(buf + sizeof(type), &timestamp, sizeof(timestamp));
					reply = (redisReply*)redisCommand(connection->context,"RPUSH %s %b", key, buf, len);
					if (reply) {
						freeReplyObject(reply);
						key_info.last_delete_time = timestamp;
						key_info.delete_count ++;
						key_info.current_version = key_info.set_count;
						key_info.set_count ++;
						//key_info.last_set_time = timestamp;
						if (!flag) {
							if (!key_info.get_count)
								key_info.set_before_get = 1;
						}
						set_key_info(key, &key_info);			
						ret = 0;
					}
				delete [] buf;
			}
		}
	} else {
		reply = (redisReply*)redisCommand(connection->context,"DEL %s", key);
		if (reply) {
			freeReplyObject(reply);
#if 0
			char *cmd = new char[max_key_len];
			if (cmd != NULL) {
				sprintf(cmd, "%s:versions", key);
				reply = (redisReply*)redisCommand(connection->context,"DEL %s", cmd);
				delete[] cmd;
				if (reply)
					freeReplyObject(reply);
			}
#endif
			ret = 0;
		}
	}
	unlock();
	return ret;
}

int TimeTravelStore::get_key_info_ex(const char *key, struct key_info_t *info)
{
	int ret = -1;

	lock();
	ret = get_key_info(key, info);
	unlock();
	return ret;
}

int TimeTravelStore::get_key_info(const char *key, struct key_info_t *info)
{
	redisReply *reply = NULL;
	int ret = -1;

	if (cache.find(key) != cache.end()) {
		memcpy(info, cache[key], sizeof(key_info_t));
		ret = 0;
		goto bail;
	}
    reply = (redisReply*)redisCommand(connection->context,"LINDEX %s 0", key);
	if (reply) {
		if (reply->type == 1) {
			if (reply->len == sizeof(key_info_t64)) {
				key_info_t64 keyinfo;

				memcpy(&keyinfo, reply->str, sizeof(key_info_t64));
				info->create_time = keyinfo.create_time;
				info->last_create_time = keyinfo.last_create_time;
				info->last_delete_time = keyinfo.last_delete_time;
				info->last_set_time = keyinfo.last_set_time;
				info->get_count = keyinfo.get_count;
				info->set_count = keyinfo.set_count;
				info->delete_count = keyinfo.delete_count;
				info->create_count = keyinfo.create_count;
				info->set_before_get = keyinfo.set_before_get;
				info->current_version = keyinfo.current_version;
				ret = 0;
			} else if (reply->len == sizeof(key_info_t)) {
				memcpy(info, reply->str, sizeof(key_info_t));
				ret = 0;
			}
			if (ret == 0) {
				key_info_t *cinfo = new key_info_t();
				if (cinfo) {
					memcpy(cinfo, info, sizeof(key_info_t));
					cache[key] = cinfo;
				}
			}
		}
		freeReplyObject(reply);
	}
bail:
	return ret;
}

int TimeTravelStore::get_key_info2(const char *key, struct key_info_t *info)
{
	redisReply *reply = NULL;
	int ret = -1;

    reply = (redisReply*)redisCommand(connection->context,"GET %s", key);
	if (reply) {
		if (reply->type == 1) {
			if (reply->len == sizeof(key_info_t64)) {
				key_info_t64 keyinfo;

				memcpy(&keyinfo, reply->str, sizeof(key_info_t64));
				info->create_time = keyinfo.create_time;
				info->last_create_time = keyinfo.last_create_time;
				info->last_delete_time = keyinfo.last_delete_time;
				info->last_set_time = keyinfo.last_set_time;
				info->get_count = keyinfo.get_count;
				info->set_count = keyinfo.set_count;
				info->delete_count = keyinfo.delete_count;
				info->create_count = keyinfo.create_count;
				info->set_before_get = keyinfo.set_before_get;
				info->current_version = keyinfo.current_version;
				ret = 0;
			} else if (reply->len == sizeof(key_info_t)) {
				memcpy(info, reply->str, sizeof(key_info_t));
				ret = 0;
			}
			freeReplyObject(reply);
		}
	}
	return ret;
}

int TimeTravelStore::set_key_info_ex(const char *key, struct key_info_t *info)
{
	int ret = -1;

	lock();
	ret = set_key_info(key, info);
	unlock();
	return ret;
}

int TimeTravelStore::set_key_info(const char *key, struct key_info_t *info)
{
	redisReply *reply = NULL;
	int ret = -1;

	if (set_key_info2(key, info) == 0) {
		redisGetReply(connection->context, (void **)&reply);
		if (reply) {
			ret = 0;
			freeReplyObject(reply);
		}
	}
	return ret;
}

int TimeTravelStore::set_key_info2(const char *key, struct key_info_t *info)
{
	redisReply *reply = NULL;
	int ret = -1;

	connection->hasupdate = 1;
	if (cache.find(key) != cache.end()) {
		memcpy(cache[key], info, sizeof(key_info_t));
	} else {
		key_info_t *cinfo = new key_info_t();
		if (cinfo) {
			memcpy(cinfo, info ,sizeof(key_info_t));
			cache[key] = cinfo;
		} else
			goto bail;
	}
	redisAppendCommand(connection->context,"LSET %s 0 %b", key, info, sizeof(key_info_t));
	ret = 0;
bail:
	return ret;
}

int TimeTravelStore::set_value(const char *key, const char *value, int valuelen, int type, double timestamp, int flag)
{
	redisReply *reply = NULL;
	key_info_t key_info;
	int len = 0;
	char *buf = NULL;
	int ret = -1;

	connection->hasupdate = 1;
	lock();
	if (get_key_info(key, &key_info)) {
		create_key(key, timestamp, 1);
		if (get_key_info(key, &key_info))
			goto error;
	}
	len = valuelen + sizeof(type) + sizeof(timestamp);
	buf = new char[len];
	if (buf) {
		memcpy(buf, &type, sizeof(type));
		memcpy(buf + sizeof(type), &timestamp, sizeof(timestamp));
		memcpy(buf + sizeof(timestamp) + sizeof(type), value, valuelen);
#if 0
			list<double> times;
			get_timestamps(key, 0, times);
			int pos = key_info.set_count - 1;
			for (list<double>::iterator it = times.begin(); it != times.end(); it++)
				if (timestamp > *it)
					break;
				else
					pos --;
			if (pos > 0) {
				// Note that format specifier other than %s and %b has to be placed after any %s or %b
				//
				sprintf(cmd, "%s:versions AFTER %d", key, pos);
				reply = (redisReply*)redisCommand(connection->context,"LINSERT %s %b", cmd, buf, len);
			} else
#endif
#if 0
			reply = (redisReply*)redisCommand(connection->context,"RPUSH %s %b", key, buf, len);
			if (reply) {
				if (reply->type != REDIS_REPLY_ERROR) {
					key_info.current_version = key_info.set_count;
					key_info.set_count ++;
					key_info.last_set_time = timestamp;
					if (!flag) {
						if (!key_info.get_count)
							key_info.set_before_get = 1;
					}
					set_key_info(key, &key_info);	
					ret = 0;
				}
				freeReplyObject(reply);
			}
#else
			redisAppendCommand(connection->context,"RPUSH %s %b", key, buf, len);
			key_info.current_version = key_info.set_count;
			if (!flag) {
				if (!key_info.get_count)
					key_info.set_before_get = 1;
				key_info.set_count ++;
				key_info.last_set_time = timestamp;
			}
			set_key_info2(key, &key_info);
			redisGetReply(connection->context, (void **)&reply);
			if (reply && reply->type != REDIS_REPLY_ERROR)
				ret = 0;
			freeReplyObject(reply);
			redisGetReply(connection->context, (void **)&reply);
			freeReplyObject(reply);
#endif
		delete [] buf;
	}
error:
	unlock();
	return ret;
}

int TimeTravelStore::get_num_versions(const char *key, double timestamp)
{
	redisReply *reply = NULL;
	int ret = -1;
	key_info_t key_info;
	int count = -1;

	if (!get_key_info(key, &key_info)) {
		reply = (redisReply*)redisCommand(connection->context, "LRANGE %s 1 -1", key);
		if (reply && reply->type == REDIS_REPLY_ARRAY) {
			char *lastvalue = new char[max_value_len];
			if (lastvalue == NULL)
				return ret;
			int lastvaluelen = 0;
			count = 0;
			for (int i = reply->elements - 1; i >= 0; i--) {
				double time;

				memcpy(&time, &(reply->element[i]->str[sizeof(int)]), sizeof(double));
				if (time < timestamp)
					// do not assume versions are saved in order
					//break; 
					continue;
				else {
					int type;
					memcpy(&type, reply->element[i]->str, sizeof(int));
					if (type == -1)
						continue;
					bool duplicate = false;
					int valuelen = reply->element[i]->len - sizeof(double) - sizeof(int);
					assert(valuelen <= max_value_len);
					if (count > 0) {
						if (strncmp(&(reply->element[i]->str[sizeof(double) + sizeof(int)]), "UNKNOWN", 7) == 0)
							duplicate = true;
						else if ((lastvaluelen == valuelen) && memcmp(lastvalue, &(reply->element[i]->str[sizeof(double) + sizeof(int)]), valuelen) == 0)
							duplicate = true;
					}
					if (!duplicate) {
						memcpy(lastvalue, &(reply->element[i]->str[sizeof(double) + sizeof(int)]), valuelen);
						lastvaluelen = valuelen;
						count++;
					}
				}
			}
			freeReplyObject(reply);
			delete[] lastvalue;
		}
	}
	return count;
}

// get timestamps of all the versions of a key that are later than specified timestamp, in the order from
// the latest to earliest into list times
int TimeTravelStore::get_timestamps(const char *key, double timestamp, list<double>& times)
{
	redisReply *reply = NULL;
	int ret = -1;
	key_info_t key_info;
	int count = -1;

	times.clear();
	if (!get_key_info(key, &key_info)) {
		reply = (redisReply*)redisCommand(connection->context, "LRANGE %s 1 -1", key);
		if (reply && reply->type == REDIS_REPLY_ARRAY) {
			char *lastvalue = new char[max_value_len];
			if (lastvalue == NULL)
				return ret;
			int lastvaluelen = 0;
			count = 0;
			for (int i = reply->elements - 1; i >= 0; i--) {
				double time;

				memcpy(&time, &(reply->element[i]->str[sizeof(int)]), sizeof(double));
				if (time < timestamp)
					// do not assume versions are saved in order
					//break;
					continue;
				else {
					int type;
					memcpy(&type, reply->element[i]->str, sizeof(int));
					if (type == -1)
						continue;
					bool duplicate = false;
					int valuelen = reply->element[i]->len - sizeof(double) - sizeof(int);
					assert(valuelen <= max_value_len);
					if (count > 0) {
						if (strncmp(&(reply->element[i]->str[sizeof(double) + sizeof(int)]), "UNKNOWN", 7) == 0)
							duplicate = true;
						else if ((lastvaluelen == valuelen) && memcmp(lastvalue, &(reply->element[i]->str[sizeof(double) + sizeof(int)]), valuelen) == 0)
							duplicate = true;
					}
					if (!duplicate) {
						memcpy(lastvalue, &(reply->element[i]->str[sizeof(double) + sizeof(int)]), valuelen);
						lastvaluelen = valuelen;
						times.push_back(time);
						count++;
					}
				}
			}
			freeReplyObject(reply);
			delete[] lastvalue;
		}
	}
	return count;
}

int TimeTravelStore::get_value(const char *key, int version, char *value, int *valuelen, int *type, double *timestamp, int flag)
{
	redisReply *reply = NULL;
	int ret = -1;
	key_info_t key_info;
	int len = 0;

	lock();
	if (get_key_info(key, &key_info)) {
		create_key(key, 0, 1);
		if (get_key_info(key, &key_info))
			goto error;
	}
	if (key_info.set_count > 0) {
		if (version < key_info.set_count) {
			if (version == -1) {// current version
				//if (!flag)
					version = key_info.current_version;
				//else
				//	version = key_info.set_count - 1;
			}
			redisAppendCommand(connection->context, "LINDEX %s %d", key, version + 1);
			if (!flag) {
				key_info.get_count ++;
				set_key_info2(key, &key_info);
			}
			redisGetReply(connection->context, (void **)&reply);
			if (reply) {
				if (reply->type == REDIS_REPLY_STRING) {
					int temp;
					memcpy(&temp, reply->str, sizeof(int));
					if (flag || temp >= 0) {
						if (type)
							*type = temp;
						if (timestamp)
							memcpy(timestamp, &reply->str[sizeof(int)], sizeof(double));
						if (valuelen)
							*valuelen = reply->len - sizeof(double) - sizeof(int);
						if (value) {
							if (valuelen) {
								if (reply->len - sizeof(double) - sizeof(int) <= *valuelen) {
									memcpy(value, &reply->str[sizeof(double) + sizeof(int)], reply->len - sizeof(double) - sizeof(int));
									*valuelen = reply->len - sizeof(double) - sizeof(int);
									ret = 0;
								}
							}
						} else
							ret = 0;
					}
				}
				freeReplyObject(reply);					
			}
			if (!flag) {
				redisGetReply(connection->context, (void **)&reply);
				freeReplyObject(reply);
			}
		}
	}
error:
	unlock();
	return ret;
}

// version: -1 set to latest version
int TimeTravelStore::set_current_version(const char *key, int version)
{
	int ret = -1;
	key_info_t key_info;

	connection->hasupdate = 1;
	lock();
	if (!get_key_info(key, &key_info)) {
		if (version >= 0 && version < key_info.set_count)
			key_info.current_version = version;
		else
			key_info.current_version = key_info.set_count - 1;
		if (!set_key_info(key, &key_info))
			ret = 0;
	}
	unlock();
	return ret;
}

int TimeTravelStore::rollback_value(const char *key, int dist)
{
	int ret = -1;
	key_info_t key_info;
	char *value = NULL, *new_value = NULL;
	int value_len;

	connection->hasupdate = 1;
	//assert(dist > 0);
	lock();
	if (!get_key_info(key, &key_info)) {
		value = new char[max_value_len];
		if (value == NULL)
			goto bail;
		new_value = new char[max_value_len];
		if (new_value == NULL)
			goto bail;
		int current_version = key_info.current_version;
		while (current_version > 0) {
			int type;
			if (get_value(key, key_info.current_version, value, &value_len, &type, NULL, 1))
				goto bail;
			if (type != -1)
				break;
			current_version --;
		}
		int rollback_num = 0;
		while (current_version > 0 && rollback_num < dist) {
			current_version --;
			int new_value_len;
			int type;
			if (get_value(key, current_version, new_value, &new_value_len, &type, NULL, 1))
				goto bail;
			if (type == -1)
				continue;
			if (new_value_len != value_len || memcmp(new_value, value, value_len)) {
				rollback_num ++;
			}
		}
		if (rollback_num == dist) {
			key_info.current_version = current_version;
			if (!set_key_info(key, &key_info))
				ret = 0;
		}
	}
bail:
	unlock();
	if (value)
		delete[] value;
	if (new_value)
		delete[] new_value;
	return ret;
}

int TimeTravelStore::flush()
{
	redisReply *reply = NULL;
	int ret = -1;

	lock();
	reply = (redisReply *)redisCommand(connection->context,"SAVE");
	if (reply) {
		freeReplyObject(reply);
		ret = 0;
		connection->hasupdate = 0;
	}
	unlock();
	return ret;
}

int TimeTravelStore::matchkeys(const char *pattern, vector<string>& keys)
{
	redisReply *reply = NULL;
	int ret = -1;
    static const char suffix[] = ":versions";
    static int suffixlen = strlen(suffix);

	keys.clear();
	char command[1024];
	sprintf(command, "KEYS %s", pattern);
	reply = (redisReply *)redisCommand(connection->context, command);
	if (reply) {
		if (reply->type == REDIS_REPLY_ARRAY) {
			int count = 0;
			for (int i = reply->elements - 1; i >= 0; i--) {
				if (strcmp(&reply->element[i]->str[strlen(reply->element[i]->str) - suffixlen], suffix))
					keys.push_back(reply->element[i]->str);
			}
		}
		freeReplyObject(reply);
		ret = 0;
	}
	return ret;
}

int TimeTravelStore::update_version(const char *key, int version, const char *value, int valuelen, int type, double timestamp)
{
	int ret = -1;

	connection->hasupdate = 1;
	char *buf = new char[max_value_len];
	if (buf != NULL) {
		int len = make_version_buf(value, valuelen, type, timestamp, buf, max_value_len);
		if (len > 0) {
				redisReply *reply = (redisReply*)redisCommand(connection->context,"LSET %s %d %b", key, version + 1, buf, len);
				if (reply) {
					ret = 0;
					freeReplyObject(reply);
				}
		}
		delete[] buf;
	}
	return ret;
}

int TimeTravelStore::make_version_buf(const char *value, int valuelen, int type, double timestamp, char *buf, int buflen)
{
	int len = valuelen + sizeof(type) + sizeof(timestamp);
	if (len > buflen)
		return -1;
	memcpy(buf, &type, sizeof(type));
	memcpy(buf + sizeof(type), &timestamp, sizeof(timestamp));
	memcpy(buf + sizeof(timestamp) + sizeof(type), value, valuelen);
	return len;
}

int TimeTravelStore::copy_key(const char *srckey, const char *destkey, double time)
{
	int ret = -1;
	key_info_t keyInfo;
	char *value = new char[max_value_len];

    if (value == NULL)
		goto bail;

	if (get_key_info_ex(srckey, &keyInfo))
		goto bail;

	if (delete_key(destkey, time, 1))
		goto bail;

	if (create_key(destkey, time))
		goto bail;
	for (int i = 0; i < keyInfo.set_count; i++) {
		int valuelen, type;
		double timestamp;
		valuelen = max_value_len;
		if (get_value(srckey, i, value, &valuelen, &type, &timestamp, 1))
			goto bail;
		if (set_value(destkey, value, valuelen, type, timestamp, 1))
			goto bail;
	}
	if (set_key_info_ex(destkey, &keyInfo) == 0)
		ret = 0;
bail:
	if (value)
		delete[] value;
	return ret;
}

int TimeTravelStore::set_latest_timestamp(const char *key, double time)
{
	int ret = -1;
	key_info_t keyInfo;
	char *value = NULL;

	if (get_key_info(key, &keyInfo) == 0) {
		value = new char[TimeTravelStore::max_value_len];
		if (value == NULL)
			goto bail;
		for (int version = keyInfo.set_count - 1; version >= 0; version--) {
			double timestamp;
			int valuelen, type;
			if (get_value(key, version, value, &valuelen, &type, &timestamp, 1))
				goto bail;
			if (type != -1 && timestamp < time && version != keyInfo.set_count - 1) 
				break;
			if (update_version(key, version, value, valuelen, type, time))
				goto bail;
		}
		ret = 0;
	}
bail:
	if (value)
		delete[] value;
	return ret;
}

int TimeTravelStore::update_value(const char *key, int version, const char *value, int valuelen, int type, double timestamp)
{
	redisReply *reply = NULL;
	key_info_t key_info;
	int len = 0;
	char *buf = NULL;
	int ret = -1;

	connection->hasupdate = 1;
	lock();
#if 0
	if (get_key_info(key, &key_info)) {
		create_key(key, timestamp, 1);
		if (get_key_info(key, &key_info))
			goto error;
	}
	if (version < 0 || version >= key_info.set_count)
		goto error;
#endif
	len = valuelen + sizeof(type) + sizeof(timestamp);
	buf = new char[len];
	if (buf) {
		if (make_version_buf(value, valuelen, type, timestamp, buf, len) < 0)
			goto error;
		reply = (redisReply*)redisCommand(connection->context,"LSET %s %d %b", key, version + 1, buf, len);
		if (reply) {
			if (reply->type != REDIS_REPLY_ERROR) {
				ret = 0;
			}
			freeReplyObject(reply);
		}
	}
error:
	unlock();
	if (buf)
		delete[] buf;
	return ret;
}
