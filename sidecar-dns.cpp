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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "sldns/config.h"
#include "sldns/sbuffer.h"
#include "dns_worker.h"
#include "dns_cache.h"
#include "dns_proxy.h"

void error(const char *msg) {
	perror(msg);
	exit(1);
}

int main(int argc, char **argv) {
	int sockfd; /* socket */
	int portno; /* port to listen on */
	int optval; /* flag value for setsockopt */
	struct sockaddr_in serveraddr; /* server's addr */

	if (argc < 4) {
		fprintf(stderr,
				"usage: %s <port> <upstream_host> <upstream_port> [datafile]\n",
				argv[0]);
		exit(1);
	}
	portno = atoi(argv[1]);

	log_init(NULL, 0, NULL);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
		error("ERROR opening socket");

	optval = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void*) &optval,
			sizeof(int));
	bzero((char*) &serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serveraddr.sin_port = htons((unsigned short) portno);
	int rc = ::bind(sockfd, (struct sockaddr*) &serveraddr,
			(socklen_t) sizeof(serveraddr));
	if (rc < 0)
		error("ERROR on binding");

	DnsCache dnsCache;
	if (!dnsCache.init()) {
		error("dnsCache.init fail");
	}

	if (argc > 4) {
		rc = dnsCache.load(argv[4]);
		log_info("\nload dns records : %d\n", rc);
	}

	DnsProxy dnsProxy;
	if (!dnsProxy.init(sockfd, argv[2], atoi(argv[3]), &dnsCache)) {
		error("dnsProxy.init fail");
	}

	DnsWorker dnsWorker(sockfd, &dnsCache, &dnsProxy);

	if (!dnsWorker.init()) {
		error("dnsWorker.init fail");
	}

	while (1) {
		dnsWorker.Process();
	}
}
