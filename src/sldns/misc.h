/*
 * misc.h
 *
 *  Created on: May 27, 2022
 *      Author: root
 */

#ifndef SRC_SLDNS_MISC_H_
#define SRC_SLDNS_MISC_H_

/** Size of an UDP datagram */
#define NORMAL_UDP_SIZE	512 /* bytes */
/** ratelimit for error responses */
#define ERROR_RATELIMIT 100 /* qps */

/** max length of an IP address (the address portion) that we allow */
#define MAX_ADDR_STRLEN 128 /* characters */
/** default value for EDNS ADVERTISED size */
//uint16_t EDNS_ADVERTISED_SIZE = 4096;
struct query_info {
	/**
	 * Salient data on the query: qname, in wireformat.
	 * can be allocated or a pointer to outside buffer.
	 * User has to keep track on the status of this.
	 */
	uint8_t *qname;
	/** length of qname (including last 0 octet) */
	size_t qname_len;
	/** qtype, host byte order */
	uint16_t qtype;
	/** qclass, host byte order */
	uint16_t qclass;
	/**
	 * Alias local answer(s) for the qname.  If 'qname' is an alias defined
	 * in a local zone, this field will be set to the corresponding local
	 * RRset when the alias is determined.
	 * In the initial implementation this can only be a single CNAME RR
	 * (or NULL), but it could possibly be extended to be a DNAME or a
	 * chain of aliases.
	 * Users of this structure are responsible to initialize this field
	 * to be NULL; otherwise other part of query handling code may be
	 * confused.
	 * Users also have to be careful about the lifetime of data.  On return
	 * from local zone lookup, it may point to data derived from
	 * configuration that may be dynamically invalidated or data allocated
	 * in an ephemeral regional allocator.  A deep copy of the data may
	 * have to be generated if it has to be kept during iterative
	 * resolution. */
	// struct local_rrset* local_alias;
};

size_t query_dname_len(sldns_buffer *query);

int query_info_parse(struct query_info *m, sldns_buffer *query);

int dname_count_size_labels(uint8_t *dname, size_t *size);

int rrstr_get_rr_content(const char *str, uint8_t **nm, uint16_t *type,
		uint16_t *dclass, time_t *ttl, uint8_t *rr, size_t len, uint8_t **rdata,
		size_t *rdata_len);

char* cfg_ptr_reverse(const char *str);

size_t pkt_dname_len(sldns_buffer *pkt);

size_t pkt_dname_byte_len(sldns_buffer *pkt);

int skip_pkt_request_rr(sldns_buffer *pkt);

int skip_pkt_rr(sldns_buffer *pkt);

int skip_pkt_rrs(sldns_buffer *pkt, int num);

int dname_pkt_copy(sldns_buffer *pkt, uint8_t *to, uint8_t *dname);

#endif /* SRC_SLDNS_MISC_H_ */
