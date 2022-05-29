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

#include "dns_worker.h"
#include "sldns/pkthdr.h"
#include "sldns/log.h"
#include "sldns/locks.h"
#include "sldns/rbtree.h"
#include "sldns/str2wire.h"
#include "sldns/misc.h"
#include "type_header.h"
#include "util.h"

int DnsWorker::init() {
	clientlen = sizeof(clientaddr);
	sbuf = sldns_buffer_new(EDNS_ADVERTISED_SIZE);
	return sbuf != nullptr;
}

DnsWorker::DnsWorker(int sockfd, DnsCache *dnsCache, DnsProxy *dnsProxy) {
	this->sockfd = sockfd;
	this->dnsCache = dnsCache;
	this->dnsProxy = dnsProxy;
}

int DnsWorker::checkRequest() {
	if (sldns_buffer_limit(sbuf) < LDNS_HEADER_SIZE) {
		verbose(VERB_QUERY, "request too short, discarded");
		return -1;
	}
	if (sldns_buffer_limit(sbuf) > NORMAL_UDP_SIZE) {
		verbose(VERB_QUERY, "request too large, discarded");
		return -2;
	}
	if (LDNS_QR_WIRE(sldns_buffer_begin(sbuf))) {
		verbose(VERB_QUERY, "request has QR bit on, discarded");
		return -3;
	}

	if (LDNS_TC_WIRE(sldns_buffer_begin(sbuf))) {
		LDNS_TC_CLR(sldns_buffer_begin(sbuf));
		verbose(VERB_QUERY, "request bad, has TC bit on");
		return LDNS_RCODE_FORMERR;
	}
	if (LDNS_OPCODE_WIRE(sldns_buffer_begin(sbuf)) != LDNS_PACKET_QUERY) {
		verbose(VERB_QUERY, "request unknown opcode %d",
				LDNS_OPCODE_WIRE(sldns_buffer_begin(sbuf)));
		return LDNS_RCODE_NOTIMPL;
	}
	if (LDNS_QDCOUNT(sldns_buffer_begin(sbuf)) != 1) {
		verbose(VERB_QUERY, "request wrong nr qd=%d",
				LDNS_QDCOUNT(sldns_buffer_begin(sbuf)));
		return LDNS_RCODE_FORMERR;
	}
	if (LDNS_ANCOUNT(sldns_buffer_begin(sbuf)) != 0) {
		verbose(VERB_QUERY, "request wrong nr an=%d",
				LDNS_ANCOUNT(sldns_buffer_begin(sbuf)));
		return LDNS_RCODE_FORMERR;
	}
	if (LDNS_NSCOUNT(sldns_buffer_begin(sbuf)) != 0) {
		verbose(VERB_QUERY, "request wrong nr ns=%d",
				LDNS_NSCOUNT(sldns_buffer_begin(sbuf)));
		return LDNS_RCODE_FORMERR;
	}

	if (LDNS_ARCOUNT(sldns_buffer_begin(sbuf)) > 1) {
		verbose(VERB_QUERY, "request wrong nr ar=%d",
				LDNS_ARCOUNT(sldns_buffer_begin(sbuf)));
		return LDNS_RCODE_FORMERR;
	}

	return 0;
}

static void responseWithRCode(sldns_buffer *sbuf, sldns_pkt_rcode rcode) {
	LDNS_QDCOUNT_SET(sldns_buffer_begin(sbuf), 0);
	LDNS_ANCOUNT_SET(sldns_buffer_begin(sbuf), 0);
	LDNS_NSCOUNT_SET(sldns_buffer_begin(sbuf), 0);
	LDNS_ARCOUNT_SET(sldns_buffer_begin(sbuf), 0);
	LDNS_QR_SET(sldns_buffer_begin(sbuf));
	LDNS_RCODE_SET(sldns_buffer_begin(sbuf), rcode);
	sldns_buffer_set_position(sbuf, LDNS_HEADER_SIZE);
	sldns_buffer_flip(sbuf);
}

int DnsWorker::handleRequest() {
	int rc = checkRequest();

	if (rc < 0) {
		return rc;
	} else if (rc > 0) {
		responseWithRCode(sbuf, (sldns_pkt_rcode) rc);
		return 1;
	}

	sldns_buffer_skip(sbuf, LDNS_HEADER_SIZE); /* skip header */

	if (!query_dname_len(sbuf)) {
		responseWithRCode(sbuf, LDNS_RCODE_FORMERR);
		return 1;
	}

	/* space available for query type and class? */
	if (sldns_buffer_remaining(sbuf) < 2 * sizeof(uint16_t)) {
		responseWithRCode(sbuf, LDNS_RCODE_FORMERR);
		return 1;
	}

	struct query_info qinfo;

	sldns_buffer_rewind(sbuf);

	if (!query_info_parse(&qinfo, sbuf)) {
		verbose(VERB_ALGO, "worker parse request: formerror.");
		responseWithRCode(sbuf, LDNS_RCODE_FORMERR);
		return 1;
	}

	sldns_buffer_rewind(sbuf);

	int length = 0;
	rc = dnsCache->query(sldns_buffer_begin(sbuf) + LDNS_HEADER_SIZE,
			qinfo.qname_len,
			sldns_buffer_begin(sbuf) + QUERY_FIXED_SIZE + qinfo.qname_len,
			EDNS_ADVERTISED_SIZE - QUERY_FIXED_SIZE + qinfo.qname_len, &length);

	if (rc > 0 && length > 0) {
		LDNS_NSCOUNT_SET(sldns_buffer_begin(sbuf), 0);
		LDNS_ARCOUNT_SET(sldns_buffer_begin(sbuf), 0);
		LDNS_QR_SET(sldns_buffer_begin(sbuf));
		LDNS_RA_SET(sldns_buffer_begin(sbuf));
		LDNS_ANCOUNT_SET(sldns_buffer_begin(sbuf), rc);
		sldns_buffer_set_limit(sbuf,
		QUERY_FIXED_SIZE + qinfo.qname_len + length);
		return 1;
	} else if (rc == 0) {
		request_client *client = (request_client*) calloc(1,
				sizeof(request_client) + qinfo.qname_len + TYPE_CLASS_LEN);
		if (!client) {
			return 0;
		}

		memcpy(&client->clientaddr, &clientaddr, sizeof(sockaddr_in));
		client->clientlen = clientlen;
		client->timestamp = time(NULL);

		memcpy(&client->dns_hdrdat, sldns_buffer_begin(sbuf),
		QUERY_FIXED_SIZE + qinfo.qname_len);
		client->name = client->dns_hdrdat.request_data;
		client->name_len = qinfo.qname_len;
		client->type = ntohs(*(uint16_t*) (client->name + client->name_len));

		int rc = dnsProxy->push_request(sldns_buffer_begin(sbuf),
				qinfo.qname_len, sldns_buffer_limit(sbuf), client);

		log_info("proxy dns, rc : %d", rc);

		if (rc < 0) {
			free(client);
		}
	} else if (rc < 0) {
		responseWithRCode(sbuf, LDNS_RCODE_REFUSED);
		return 1;
	}

	return 0;
}

int DnsWorker::Process() {

	clientlen = sizeof(clientaddr);

	int n = recvfrom(sockfd, sbuf->_data, sbuf->_capacity, 0,
			(struct sockaddr*) &clientaddr, &clientlen);

	sldns_buffer_set_limit(sbuf, n);

	int rc = handleRequest();

	if (rc > 0) {
		n = sendto(sockfd, sbuf->_data, sbuf->_limit, 0,
				(struct sockaddr*) &clientaddr, clientlen);

		if (n < 0) {
			verbose(VERB_QUERY, "ERROR in sendto");
		}
	}

	return 0;
}
