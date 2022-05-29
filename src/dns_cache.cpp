/*
 *  Copyright (c) 2019 by flomesh.io
 *
 *  Unless prior written consent has been obtained from the copyright
 *  owner, the following shall not be allowed.
 *
 *  1. The distribution of any source codes, header files, make files,
 *     or libraries of the software.
 *
 *  2. Disclosure of any source codes pertaining to the software to any
 *     additional parties.
 *
 *  3. Alteration or removal of any notices in or on the software or
 *     within the documentation included within the software.
 *
 *  ALL SOURCE CODE AS WELL AS ALL DOCUMENTATION INCLUDED WITH THIS
 *  SOFTWARE IS PROVIDED IN AN “AS IS” CONDITION, WITHOUT WARRANTY OF ANY
 *  KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 *  OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 *  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 *  CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 *  TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 *  SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <chrono>
#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>
#include "dns_cache.h"
#include "util.h"
#include "sldns/misc.h"
#include "sldns/rrdef.h"
#include "type_header.h"

using namespace std;

DnsCache::~DnsCache() {
}

uint32_t DnsCache::calc_ttl(resource_record *rr) {
	uint32_t pos = position;

	if (rr->ttl_position >= pos) {
		return rr->ttl_position - pos;
	}

	return rr->ttl_position + MAX_TTL_BUCKET - pos;
}

int DnsCache::assign_ttl_bucket(resource_record *rr) {
	if (rr->ttl_original >= MAX_TTL_BUCKET) {
		rr->ttl_original = MAX_TTL_BUCKET - 1;
	}

	lock_rw_wrlock(&ttl_lock);
	rr->ttl_position = (position + rr->ttl_original) % MAX_TTL_BUCKET;
	list_insert(&ttl_bucket[rr->ttl_position], rr);
	lock_rw_unlock(&ttl_lock);

	return 0;
}

void DnsCache::ttl_function() {
	int64_t elapse_clock = 0;
	resource_record *head, *rr;

	while (!quit) {
		if (elapse_clock < 1000) {
			std::this_thread::sleep_for(
					std::chrono::milliseconds(1000 - elapse_clock));
		}
		elapse_clock = getSteadyMillis();

		lock_rw_wrlock(&ttl_lock);
		head = ttl_bucket[position];
		ttl_bucket[position] = nullptr;
		position = (position + 1) % MAX_TTL_BUCKET;
		lock_rw_unlock(&ttl_lock);

		while (head) {
			rr = head;
			list_remove(&head, rr);
			if (!rr->is_local || assign_ttl_bucket(rr) < 0) {
				remove_resource_record(rr);
			}
		}

		elapse_clock = getSteadyMillis() - elapse_clock;
	}
}

bool DnsCache::init() {
	lock_rw_init(&cache_lock);

	lock_rw_init(&ttl_lock);

	memset(ttl_bucket, 0, sizeof(ttl_bucket));

	ttl_thread = std::thread(&DnsCache::ttl_function, this);
	ttl_thread.detach();

	cache_tree = rbtree_create(cmp_name_type);
	if (!cache_tree) {
		log_err("DnsCache Initialization failed.");
		return false;
	}

	return true;
}

std::string& ltrim(std::string &s) {
	auto it = std::find_if(s.begin(), s.end(), [](char c) {
		return !std::isspace<char>(c, std::locale::classic());
	});
	s.erase(s.begin(), it);
	return s;
}

std::string& rtrim(std::string &s) {
	auto it = std::find_if(s.rbegin(), s.rend(), [](char c) {
		return !std::isspace<char>(c, std::locale::classic());
	});
	s.erase(it.base(), s.end());
	return s;
}

std::string& trim(std::string &s) {
	return ltrim(rtrim(s));
}

bool startsWith(const std::string &str, const std::string &prefix) {
	return str.size() >= prefix.size() && str.substr(0, prefix.size()) == prefix;
}

int DnsCache::load(const char *config_file) {
	int rc = 0;
	string line;
	ifstream myfile(config_file);

	if (myfile.is_open()) {
		while (getline(myfile, line)) {
			line = trim(line);
			cout << line << '\n';

			if (line.length() < 5 || startsWith(line, "#")) {
				continue;
			}

			if (startsWith(line, "ptr:")) {
				line = cfg_ptr_reverse((char*) line.substr(4).c_str());
			}

			uint8_t is_refuse = 0;
			if (startsWith(line, "---:")) {
				is_refuse = 1;
				line = line.substr(4).c_str();
			}
			line = trim(line);

			resource_record *rr = rrstr2dnsrr(line.c_str());
			if (rr) {
				rr->is_refuse = is_refuse;
				insert_resource_record(rr);
				rc++;
			}
		}
		myfile.close();
	}

	return rc;
}

int DnsCache::insert_resource_record(resource_record *rr) {
	int rc = 0;
	rbnode_type *node;

	lock_rw_wrlock(&cache_lock);

	node = rbtree_search(cache_tree, rr->name);

	if (!node) {
		node = (rbnode_type*) calloc(1, sizeof(rbnode_type));

		if (!node) {
			lock_rw_unlock(&cache_lock);
			return -1;
		}

		int key_len = rr->name_len + sizeof(rr->meta->type);

		cache_data *data = (cache_data*) calloc(1,
				sizeof(cache_data) + key_len);

		if (!data) {
			free(node);
			lock_rw_unlock(&cache_lock);
			return -2;
		}

		memcpy(data->name_type, rr->name, key_len);
		data->name_len = rr->name_len;
		data->rr_data[data->count++] = rr;
		data->type = ntohs(rr->meta->type);
		data->clazz = ntohs(rr->meta->clazz);

		node->key = ((char*) data) + CACHE_NAME_OFFSET;
		rbtree_insert(cache_tree, node);
	} else {
		cache_data *data = (cache_data*) ((char*) node->key - CACHE_NAME_OFFSET);

		if (data->count == MAX_RR_DATA_SIZE) {
			lock_rw_unlock(&cache_lock);
			return -3;
		}
		for (int i = 0; i < data->count; i++) {
			if (data->rr_data[i]->meta->resp_len != rr->meta->resp_len) {
				continue;
			}
			if (memcmp(data->rr_data[i]->meta->resp_data, rr->meta->resp_data,
					ntohs(rr->meta->resp_len)) == 0) {
				lock_rw_unlock(&cache_lock);
				return -4;
			}
		}
		data->rr_data[data->count++] = rr;
	}

	rc = assign_ttl_bucket(rr);

	lock_rw_unlock(&cache_lock);

	return rc;
}

int DnsCache::remove_resource_record(resource_record *rr) {
	rbnode_type *node;
	cache_data *data = nullptr;

	lock_rw_wrlock(&cache_lock);

	node = rbtree_search(cache_tree, rr->name);

	if (!node) {
		free(rr);
		lock_rw_unlock(&cache_lock);
		return -1;
	}

	data = (cache_data*) ((char*) node->key - CACHE_NAME_OFFSET);

	for (int i = 0; i < data->count; i++) {
		if (data->rr_data[i] == rr) {
			int after_size = data->count - i - 1;

			if (after_size > 0) {
				memmove(&data->rr_data[i], &data->rr_data[i + 1],
						sizeof(resource_record*) * after_size);
			}
			data->count--;
			break;
		}
	}

	if (data->count > 0) {
		data = nullptr;
	} else {
		rbtree_delete(cache_tree, node->key);
	}

	lock_rw_unlock(&cache_lock);

	if (data) {
		free(data);
		free(node);
	}
	free(rr);

	return 0;
}

cache_data* DnsCache::find_by_name_type(const void *key) {
	rbnode_type *type = rbtree_search(cache_tree, key);

	if (type) {
		return (cache_data*) ((char*) type->key - CACHE_NAME_OFFSET);
	}
	return nullptr;
}

int DnsCache::query(const void *key, int name_len, void *buffer, int size,
		int *length) {
	int rc = 0;
	int len = 0;
	int is_refuse = 0;
	cache_data *data;
	uint16_t *ptype = (uint16_t*) ((char*) key + name_len);
	uint16_t ntype = *ptype;
	uint16_t htype = ntohs(ntype);

	lock_rw_rdlock(&cache_lock);

	data = find_by_name_type(key);

	if (!data && (htype == LDNS_RR_TYPE_A || htype == LDNS_RR_TYPE_AAAA)) {
		*ptype = htons(LDNS_RR_TYPE_CNAME);
		data = find_by_name_type(key);
		*ptype = ntype;
	}

	if (!data) {
		lock_rw_unlock(&cache_lock);
		return 0;
	}

	int pos = data->index++;

	for (int i = 0; i < data->count; i++) {
		int n = (pos + i) % data->count;
		resource_record *rr = data->rr_data[n];

		is_refuse |= rr->is_refuse;

		if (len + (int) rr->length > size) {
			break;
		}

		memcpy((char*) buffer + len, (char*) rr->name, rr->length);

		*((uint32_t*) ((char*) buffer + len + rr->name_len + TYPE_CLASS_LEN)) =
				htonl(calc_ttl(rr));

		len += rr->length;

		if (rr->meta->type == htons(LDNS_RR_TYPE_CNAME) && rr->cname_len > 0) {
			int cname_len = ntohs(rr->meta->resp_len);
			char cname[LDNS_MAX_DOMAINLEN + TYPE_CLASS_LEN];

			memcpy(cname, rr->meta->resp_data, cname_len);
			*((uint16_t*) &cname[cname_len]) = ntype;

			int rx, nx = 0;
			rx = query(cname, cname_len, (char*) buffer + len, size - len, &nx);
			if (rx > 0) {
				rc += rx;
				len += nx;
			} else if (htype == LDNS_RR_TYPE_A || htype == LDNS_RR_TYPE_AAAA) {
				lock_rw_unlock(&cache_lock);
				return 0;
			}
		}
		++rc;
	}

	*length = len;
	lock_rw_unlock(&cache_lock);

	if (is_refuse > 0) {
		return -1;
	}

	return rc;
}
