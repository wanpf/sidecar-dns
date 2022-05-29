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

#ifndef SRC_DNS_WORKER_H_
#define SRC_DNS_WORKER_H_

#include "sldns/config.h"
#include "sldns/sbuffer.h"
#include "dns_cache.h"
#include "dns_proxy.h"

class DnsWorker final {
public:
	DnsWorker(int sockfd, DnsCache *dnsCache, DnsProxy *dnsProxy);

	int Process();

	int init();

private:
	int checkRequest();

	int handleRequest();

	// DNS服务器监听socket
	int sockfd;

	// 负责DNS缓存的处理类
	DnsCache *dnsCache;

	// 负责将DNS请求转发到上游的处理类
	DnsProxy *dnsProxy;

	// 接收网络数据的buffer
	sldns_buffer *sbuf;

	// 客户端地址长度
	socklen_t clientlen;

	// 保存客户端地址
	struct sockaddr_in clientaddr;
};

#endif /* SRC_DNS_WORKER_H_ */
