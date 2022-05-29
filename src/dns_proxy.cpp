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

#include <dns_proxy.h>
#include "util.h"
#include "type_header.h"
#include "sldns/misc.h"
#include "sldns/log.h"
#include "sldns/rrdef.h"
#include "sldns/sbuffer.h"
#include "sldns/pkthdr.h"
#include <iostream>
#include <chrono>
#include <queue>

DnsProxy::~DnsProxy() {
}

request_task* DnsProxy::find_by_name_type(const void *key) {
	rbnode_type *type = rbtree_search(task_tree, key);

	if (type) {
		return (request_task*) ((char*) type->key - DNS_HDRDAT_OFFSET);
	}
	return NULL;
}

request_task* DnsProxy::delete_task(request_task *task) {
	rbnode_type *node = nullptr;
	request_task *old = task;

	node = rbtree_search(task_tree, (char*) task + DNS_HDRDAT_OFFSET);
	if (node) {
		rbtree_delete(task_tree, node->key);
		free(node);
	}
	task = list_remove(&task_list, task);

	request_client *client = old->client_list;
	while (client) {
		request_client *tmp = client;
		client = list_remove(&old->client_list, client);
		free(tmp);
	}
	free(old);

	return task;
}

request_task* DnsProxy::detach_by_name_type(const void *key) {
	rbnode_type *type;
	request_task *task = nullptr;

	lock_rw_wrlock(&task_lock);
	type = rbtree_search(task_tree, key);
	if (type) {
		task = (request_task*) ((char*) type->key - DNS_HDRDAT_OFFSET);

		list_remove(&task_list, task);
		rbtree_delete(task_tree, type->key);
		free(type);
	}
	lock_rw_unlock(&task_lock);

	return task;
}

int DnsProxy::cache_resource_record(sldns_buffer *sbuf, uint16_t count) {
	int i;
	uint8_t name[LDNS_MAX_DOMAINLEN];
	uint8_t buffer[EDNS_ADVERTISED_SIZE];

	for (i = 0; i < count; i++) {
		size_t pos = sldns_buffer_position(sbuf);
		int byte_len = pkt_dname_byte_len(sbuf);
		if (byte_len == 0 || byte_len > LDNS_MAX_DOMAINLEN) {
			break;
		}

		int name_len = dname_pkt_copy(sbuf, name, sldns_buffer_at(sbuf, pos));
		resource_record *rr = (resource_record*) buffer;

		sldns_buffer_set_position(sbuf, pos + byte_len);

		rr->timestamp = time(NULL);
		memcpy(rr->name, name, name_len);
		rr->name_len = name_len;
		rr->meta = (resource_meta*) (rr->name + name_len);
		rr->meta->type = htons(sldns_buffer_read_u16(sbuf));
		rr->meta->clazz = htons(sldns_buffer_read_u16(sbuf));
		rr->meta->ttl = sldns_buffer_read_u32(sbuf);

		int resp_len = sldns_buffer_read_u16(sbuf);
		if (resp_len > LDNS_MAX_DOMAINLEN) {
			break;
		}
		rr->meta->resp_len = htons(resp_len);
		memcpy(rr->meta->resp_data, sldns_buffer_current(sbuf), resp_len);

		if (ntohs(rr->meta->type) == LDNS_RR_TYPE_CNAME) {
			pos = sldns_buffer_position(sbuf);
			byte_len = pkt_dname_byte_len(sbuf);
			if (byte_len == 0 || byte_len > LDNS_MAX_DOMAINLEN) {
				break;
			}
			sldns_buffer_set_position(sbuf, pos);
			name_len = dname_pkt_copy(sbuf, name, sldns_buffer_current(sbuf));

			if (name_len > byte_len) {
				int left = resp_len - byte_len;
				if (left < 0) {
					break;
				}
				memcpy(rr->meta->resp_data, name, name_len);
				memcpy(rr->meta->resp_data + name_len,
						sldns_buffer_at(sbuf, pos + byte_len), left);
				rr->meta->resp_len = htons(left + name_len);
			}
			if (name_len >= byte_len) {
				rr->cname_len = name_len;
			}
		}
		sldns_buffer_skip(sbuf, resp_len);
		rr->length = rr->name_len + TYPE_CLASS_TTL_LEN
				+ ntohs(rr->meta->resp_len);
		rr->ttl_original = rr->meta->ttl;

		int size = sizeof(resource_record) + rr->length;
		resource_record *nrr = (resource_record*) calloc(1, size);
		memcpy(nrr, rr, size);
		nrr->meta = (resource_meta*) (nrr->name + nrr->name_len);

		if (dnsCache->insert_resource_record(nrr) < 0) {
			free(nrr);
		}
	}
	return i;
}

void DnsProxy::receive_function() {
	sldns_buffer *sbuf = sldns_buffer_new(EDNS_ADVERTISED_SIZE);
	dns_hdr_dat *hdrdat;
	request_task *task;

	while (!quit) {
		int i;
		sldns_buffer_clear(sbuf);

		int n = recv(proxySocket, sldns_buffer_begin(sbuf),
				sldns_buffer_capacity(sbuf), 0);
		if (n < LDNS_HEADER_SIZE) {
			continue;
		}
		sldns_buffer_set_position(sbuf, n);
		hdrdat = (dns_hdr_dat*) sldns_buffer_begin(sbuf);

		if (ntohs(hdrdat->qcount) != 1) {
			continue;
		}
		sldns_buffer_set_position(sbuf, LDNS_HEADER_SIZE);
		if (!skip_pkt_request_rr(sbuf)) {
			continue;
		}

		size_t request_end = sldns_buffer_position(sbuf);
		int name_len = request_end - QUERY_FIXED_SIZE;
		if (name_len < 1) {
			continue;
		}

		hdrdat->adcount = 0;

		uint16_t ancount = ntohs(hdrdat->ancount);
		if (cache_resource_record(sbuf, ancount) != ancount) {
			continue;
		}
		log_info("push rr ancount: %d", ancount);

		uint16_t nscount = ntohs(hdrdat->nscount);
		if (cache_resource_record(sbuf, nscount) != nscount) {
			continue;
		}
		log_info("push rr nscount: %d", nscount);

		task = detach_by_name_type(hdrdat->request_data);
		if (!task) {
			continue;
		}
		while (task->client_list) {
			request_client *client = task->client_list;

			int length = 0;
			int rc = dnsCache->query(client->name, client->name_len,
					sldns_buffer_begin(sbuf) + QUERY_FIXED_SIZE
							+ client->name_len,
					EDNS_ADVERTISED_SIZE - QUERY_FIXED_SIZE - client->name_len,
					&length);

			if (rc > 0) {
				memcpy(hdrdat, &client->dns_hdrdat,
				QUERY_FIXED_SIZE + client->name_len);

				log_info("hit cache count : %d", rc);

				hdrdat->qr = 1;
				hdrdat->ra = 1;
				hdrdat->ancount = htons(rc);
				sldns_buffer_set_limit(sbuf,
				QUERY_FIXED_SIZE + name_len + length);

				int n = sendto(serverSocket, sldns_buffer_begin(sbuf),
						sldns_buffer_limit(sbuf), 0,
						(struct sockaddr*) &client->clientaddr,
						client->clientlen);
				if (n < 0) {
					log_err("send client dns reply error");
				} else {
					log_info("send client dns reply ok");
				}
			}

			list_remove(&task->client_list, client);
			free(client);
		}
		free(task);
	}
}

void DnsProxy::task_function() {
	while (!quit) {
		std::this_thread::sleep_for(std::chrono::milliseconds(100));

		lock_rw_wrlock(&task_lock);

		uint64_t nowClock = getSteadyMillis();
		uint64_t expireClock = nowClock - 3000;
		uint64_t resendClock = nowClock - 1500;

		request_task *task = task_list;

		while (task) {
			if (task->clock_millisecond < expireClock) {
				task = delete_task(task);
			} else if (task->clock_millisecond < resendClock
					&& task->sent_count++ < 2) {

				int n = send(proxySocket, &task->dns_hdrdat,
						task->request_length, 0);
				if (n < 0) {
					log_err("resend dns query fail");
				}
				task = task->succ;
			} else {
				break;
			}
			if (task == task_list) {
				break;
			}
		}

		lock_rw_unlock(&task_lock);
	}
}

int DnsProxy::push_request(uint8_t *data, int name_len, int length,
		request_client *client) {
	int newTask = 0;
	rbnode_type *node;
	request_task *task;

	lock_rw_wrlock(&task_lock);

	task = find_by_name_type(data + LDNS_HEADER_SIZE);

	if (!task) {
		node = (rbnode_type*) calloc(1, sizeof(rbnode_type));
		if (!node) {
			lock_rw_unlock(&task_lock);
			return -1;
		}

		task = (request_task*) calloc(1,
				sizeof(request_task) + EDNS_ADVERTISED_SIZE);
		if (!task) {
			lock_rw_unlock(&task_lock);
			return -2;
		}

		task->clock_millisecond = getSteadyMillis();
		task->buffer_size = EDNS_ADVERTISED_SIZE;
		memcpy(&task->dns_hdrdat, data, length);
		task->name = task->dns_hdrdat.request_data;
		task->name_len = name_len;
		task->type = *(uint16_t*) ((char*) &task->dns_hdrdat.request_data
				+ name_len);
		task->dns_hdrdat.adcount = 0;
		task->request_length = name_len + QUERY_FIXED_SIZE;
		task->sent_count = 1;

		node->key = (char*) task + DNS_HDRDAT_OFFSET;
		rbtree_insert(task_tree, node);
		list_insert(&task_list, task);
		newTask = 1;
	}

	list_insert(&task->client_list, client);
	lock_rw_unlock(&task_lock);

	if (newTask) {
		int n = send(proxySocket, &task->dns_hdrdat, task->request_length, 0);
		if (n < 0) {
			log_err("send DNS request failed errno : %d", errno);
		}
	}

	return 0;
}

bool DnsProxy::init(int serverSocket, const string &host, uint16_t port,
		DnsCache *dnsCache) {

	this->serverSocket = serverSocket;
	this->hostname = host;
	this->port = port;
	this->dnsCache = dnsCache;

	lock_rw_init(&task_lock);

	proxySocket = socket(AF_INET, SOCK_DGRAM, 0);
	if (proxySocket < 0) {
		log_err("ERROR opening socket");
		return false;
	}

	int optval = 1;
	setsockopt(proxySocket, SOL_SOCKET, SO_REUSEADDR, (const void*) &optval,
			sizeof(int));

	struct sockaddr_in serveraddr;
	bzero((char*) &serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serveraddr.sin_port = htons((unsigned short) 10053);

	if (::bind(proxySocket, (struct sockaddr*) &serveraddr, sizeof(serveraddr))
			< 0) {
		log_err("ERROR on binding");
		return false;
	}

	struct sockaddr_in remoteaddr;
	bzero((char*) &remoteaddr, sizeof(remoteaddr));
	remoteaddr.sin_family = AF_INET;
	if (inet_pton(AF_INET, hostname.c_str(), &remoteaddr.sin_addr) <= 0) {
		log_err("Invalid address/ Address not supported");
		return false;
	}
	remoteaddr.sin_port = htons((unsigned short) port);
	if (connect(proxySocket, (const struct sockaddr*) &remoteaddr,
			sizeof(remoteaddr)) < 0) {
		log_err("Error : Connect Failed");
		return false;
	}

	task_tree = rbtree_create(cmp_name_type);
	if (!task_tree) {
		log_err("DnsProxy Initialization failed.");
		return false;
	}

	receive_thread = std::thread(&DnsProxy::receive_function, this);
	receive_thread.detach();
	task_thread = std::thread(&DnsProxy::task_function, this);
	task_thread.detach();

	return true;
}
