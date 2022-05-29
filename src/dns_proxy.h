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

#ifndef DNS_PROXY_H_
#define DNS_PROXY_H_

#include <thread>
#include <atomic>
#include <string>
#include "sldns/config.h"
#include "sldns/locks.h"
#include "sldns/rbtree.h"
#include "type_header.h"
#include "dns_cache.h"

using namespace std;

class DnsProxy final {

public:
	virtual ~DnsProxy();

	bool init(int serverSocket, const string &host, uint16_t port,
			DnsCache *dnsCache);

	int push_request(uint8_t *data, int name_len, int length,
			request_client *client);

private:
	void task_function();
	void receive_function();
	request_task* find_by_name_type(const void *key);
	request_task* detach_by_name_type(const void *key);
	request_task* delete_task(request_task *task);
	int cache_resource_record(sldns_buffer *sbuf, uint16_t count);

	DnsCache *dnsCache = nullptr;
	string hostname;
	uint16_t port;

	int proxySocket;
	int serverSocket;

	lock_rw_type task_lock;
	rbtree_type *task_tree = nullptr;

	std::atomic<bool> quit;
	std::thread receive_thread;
	std::thread task_thread;
	request_task *task_list = nullptr;
};

#endif /* SRC_DNS_PROXY_H_ */
