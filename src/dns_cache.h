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

#ifndef DNS_CACHE_H_
#define DNS_CACHE_H_

#include <queue>
#include <thread>
#include <atomic>
#include "sldns/config.h"
#include "sldns/locks.h"
#include "sldns/rbtree.h"
#include "type_header.h"

#define MAX_TTL_BUCKET (600) // must > 0

class DnsCache final {

public:
	virtual ~DnsCache();

	bool init();

	int load(const char *config_file);

	int query(const void *key, int name_len, void *buffer, int size,
			int *length);

	int insert_resource_record(resource_record *rr);

	int remove_resource_record(resource_record *rr);

private:
	void ttl_function();
	uint32_t calc_ttl(resource_record *rr);
	int assign_ttl_bucket(resource_record *rr);
	cache_data* find_by_name_type(const void *key);

	lock_rw_type cache_lock;
	rbtree_type *cache_tree = nullptr;

	int position = 0;
	lock_rw_type ttl_lock;
	std::atomic<bool> quit;
	std::thread ttl_thread;
	resource_record *ttl_bucket[MAX_TTL_BUCKET];
};

#endif /* DNS_CACHE_H_ */
