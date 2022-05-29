/*
 * misc.c
 *
 *  Created on: May 27, 2022
 *      Author: root
 */

#include <string.h>
#include <time.h>

#include "sldns/config.h"
#include "sldns/log.h"
#include "sldns/pkthdr.h"
#include "sldns/str2wire.h"
#include "sldns/sbuffer.h"
#include "sldns/rrdef.h"
#include "type_header.h"
#include "misc.h"

int dname_count_size_labels(uint8_t *dname, size_t *size) {
	uint8_t lablen;
	int labs = 1;
	size_t sz = 1;

	lablen = *dname++;
	while (lablen) {
		labs++;
		sz += lablen + 1;
		dname += lablen;
		lablen = *dname++;
	}
	*size = sz;
	return labs;
}

static void* memdup(void *data, size_t len) {
	void *d;
	if (!data)
		return NULL;
	if (len == 0)
		return NULL;
	d = malloc(len);
	if (!d)
		return NULL;
	memcpy(d, data, len);
	return d;
}

int rrstr_get_rr_content(const char *str, uint8_t **nm, uint16_t *type,
		uint16_t *dclass, time_t *ttl, uint8_t *rr, size_t len, uint8_t **rdata,
		size_t *rdata_len) {
	size_t dname_len = 0;
	int e = sldns_str2wire_rr_buf(str, rr, &len, &dname_len, 3600, NULL, 0,
	NULL, 0);
	if (e) {
		log_err("error parsing local-data at %d: '%s': %s",
				LDNS_WIREPARSE_OFFSET(e), str, sldns_get_errorstr_parse(e));
		return 0;
	}
	*nm = (uint8_t*) memdup(rr, dname_len);
	if (!*nm) {
		log_err("out of memory");
		return 0;
	}
	*dclass = sldns_wirerr_get_class(rr, len, dname_len);
	*type = sldns_wirerr_get_type(rr, len, dname_len);
	*ttl = (time_t) sldns_wirerr_get_ttl(rr, len, dname_len);
	//*rdata = sldns_wirerr_get_rdatawl(rr, len, dname_len);
	//*rdata_len = sldns_wirerr_get_rdatalen(rr, len, dname_len) + 2;
	*rdata = sldns_wirerr_get_rdatawl(rr, len, dname_len) + 2;
	*rdata_len = sldns_wirerr_get_rdatalen(rr, len, dname_len);
	return 1;
}

/** return next space character in string */
static char* next_space_pos(char *str) {
	char *sp = strchr(str, ' ');
	char *tab = strchr(str, '\t');
	if (!tab && !sp)
		return NULL;
	if (!sp)
		return tab;
	if (!tab)
		return sp;
	return (sp < tab) ? sp : tab;
}

/** return last space character in string */
static char* last_space_pos(char *str) {
	char *sp = strrchr(str, ' ');
	char *tab = strrchr(str, '\t');
	if (!tab && !sp)
		return NULL;
	if (!sp)
		return tab;
	if (!tab)
		return sp;
	return (sp > tab) ? sp : tab;
}

/* returns true is string addr is an ip6 specced address */
int str_is_ip6(const char *str) {
	if (strchr(str, ':'))
		return 1;
	else
		return 0;
}

int ipstrtoaddr(const char *ip, int port, struct sockaddr_storage *addr,
		socklen_t *addrlen) {
	uint16_t p;
	if (!ip)
		return 0;
	p = (uint16_t) port;
	if (str_is_ip6(ip)) {
		char buf[MAX_ADDR_STRLEN];
		char *s;
		struct sockaddr_in6 *sa = (struct sockaddr_in6*) addr;
		*addrlen = (socklen_t) sizeof(struct sockaddr_in6);
		memset(sa, 0, *addrlen);
		sa->sin6_family = AF_INET6;
		sa->sin6_port = (in_port_t) htons(p);
		if ((s = strchr((char*) ip, '%'))) { /* ip6%interface, rfc 4007 */
			if (s - ip >= MAX_ADDR_STRLEN)
				return 0;
			(void) strncpy(buf, ip, sizeof(buf));
			buf[s - ip] = 0;
#ifdef HAVE_IF_NAMETOINDEX000
			if (!(sa->sin6_scope_id = if_nametoindex(s+1)))
#endif /* HAVE_IF_NAMETOINDEX */
			sa->sin6_scope_id = (uint32_t) atoi(s + 1);
			ip = buf;
		}
		if (inet_pton((int) sa->sin6_family, ip, &sa->sin6_addr) <= 0) {
			return 0;
		}
	} else { /* ip4 */
		struct sockaddr_in *sa = (struct sockaddr_in*) addr;
		*addrlen = (socklen_t) sizeof(struct sockaddr_in);
		memset(sa, 0, *addrlen);
		sa->sin_family = AF_INET;
		sa->sin_port = (in_port_t) htons(p);
		if (inet_pton((int) sa->sin_family, ip, &sa->sin_addr) <= 0) {
			return 0;
		}
	}
	return 1;
}

int addr_is_ip6(struct sockaddr_storage *addr, socklen_t len) {
	if (len == (socklen_t) sizeof(struct sockaddr_in6)&&
	((struct sockaddr_in6*)addr)->sin6_family == AF_INET6)
		return 1;
	else
		return 0;
}

char* cfg_ptr_reverse(const char *str) {
	char *ip, *ip_end;
	char *name;
	char *result;
	char buf[1024];
	struct sockaddr_storage addr;
	socklen_t addrlen;

	/* parse it as: [IP] [between stuff] [name] */
	ip = (char*) str;
	while (*ip && isspace((unsigned char ) *ip))
		ip++;
	if (!*ip) {
		log_err("syntax error: too short: %s", str);
		return NULL;
	}
	ip_end = next_space_pos(ip);
	if (!ip_end || !*ip_end) {
		log_err("syntax error: expected name: %s", str);
		return NULL;
	}

	name = last_space_pos(ip_end);
	if (!name || !*name) {
		log_err("syntax error: expected name: %s", str);
		return NULL;
	}

	sscanf(ip, "%100s", buf);
	buf[sizeof(buf) - 1] = 0;

	if (!ipstrtoaddr(buf, UNBOUND_DNS_PORT, &addr, &addrlen)) {
		log_err("syntax error: cannot parse address: %s", str);
		return NULL;
	}

	/* reverse IPv4:
	 * ddd.ddd.ddd.ddd.in-addr-arpa.
	 * IPv6: (h.){32}.ip6.arpa.  */

	if (addr_is_ip6(&addr, addrlen)) {
		uint8_t ad[16];
		const char *hex = "0123456789abcdef";
		char *p = buf;
		int i;
		memmove(ad, &((struct sockaddr_in6*) &addr)->sin6_addr, sizeof(ad));
		for (i = 15; i >= 0; i--) {
			uint8_t b = ad[i];
			*p++ = hex[(b & 0x0f)];
			*p++ = '.';
			*p++ = hex[(b & 0xf0) >> 4];
			*p++ = '.';
		}
		snprintf(buf + 16 * 4, sizeof(buf) - 16 * 4, "ip6.arpa. ");
	} else {
		uint8_t ad[4];
		memmove(ad, &((struct sockaddr_in*) &addr)->sin_addr, sizeof(ad));
		snprintf(buf, sizeof(buf), "%u.%u.%u.%u.in-addr.arpa. ",
				(unsigned) ad[3], (unsigned) ad[2], (unsigned) ad[1],
				(unsigned) ad[0]);
	}

	/* printed the reverse address, now the between goop and name on end */
	while (*ip_end && isspace((unsigned char ) *ip_end))
		ip_end++;
	if (name > ip_end) {
		snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "%.*s",
				(int) (name - ip_end), ip_end);
	}
	snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), " PTR %s", name);

	result = strdup(buf);
	if (!result) {
		log_err("out of memory parsing %s", str);
		return NULL;
	}
	return result;
}

/** Check if label length is first octet of a compression pointer, pass u8. */
#define LABEL_IS_PTR(x) ( ((x)&0xc0) == 0xc0 )
/** Calculate destination offset of a compression pointer. pass first and
 * second octets of the compression pointer. */
#define PTR_OFFSET(x, y) ( ((x)&0x3f)<<8 | (y) )
/** create a compression pointer to the given offset. */
#define PTR_CREATE(offset) ((uint16_t)(0xc000 | (offset)))

/** error codes, extended with EDNS, so > 15. */
#define EDNS_RCODE_BADVERS	16	/** bad EDNS version */
/** largest valid compression offset */
#define PTR_MAX_OFFSET 	0x3fff

/** max number of compression ptrs to follow */
#define MAX_COMPRESS_PTRS 256

size_t pkt_dname_len(sldns_buffer *pkt) {
	size_t len = 0;
	int ptrcount = 0;
	uint8_t labellen;
	size_t endpos = 0;

	/* read dname and determine length */
	/* check compression pointers, loops, out of bounds */
	while (1) {
		/* read next label */
		if (sldns_buffer_remaining(pkt) < 1)
			return 0;
		labellen = sldns_buffer_read_u8(pkt);
		if (LABEL_IS_PTR(labellen)) {
			/* compression ptr */
			uint16_t ptr;
			if (sldns_buffer_remaining(pkt) < 1)
				return 0;
			ptr = PTR_OFFSET(labellen, sldns_buffer_read_u8(pkt));
			if (ptrcount++ > MAX_COMPRESS_PTRS)
				return 0; /* loop! */
			if (sldns_buffer_limit(pkt) <= ptr)
				return 0; /* out of bounds! */
			if (!endpos)
				endpos = sldns_buffer_position(pkt);
			sldns_buffer_set_position(pkt, ptr);
		} else {
			/* label contents */
			if (labellen > 0x3f)
				return 0; /* label too long */
			len += 1 + labellen;
			if (len > LDNS_MAX_DOMAINLEN)
				return 0;
			if (labellen == 0) {
				/* end of dname */
				break;
			}
			if (sldns_buffer_remaining(pkt) < labellen)
				return 0;
			sldns_buffer_skip(pkt, (ssize_t) labellen);
		}
	}
	if (endpos)
		sldns_buffer_set_position(pkt, endpos);

	return len;
}

size_t pkt_dname_byte_len(sldns_buffer *pkt) {
	size_t len = 0;
	int ptrcount = 0;
	uint8_t labellen;
	size_t endpos = 0;

	size_t pos = sldns_buffer_position(pkt);

	/* read dname and determine length */
	/* check compression pointers, loops, out of bounds */
	while (1) {
		/* read next label */
		if (sldns_buffer_remaining(pkt) < 1)
			return 0;
		labellen = sldns_buffer_read_u8(pkt);
		if (LABEL_IS_PTR(labellen)) {
			/* compression ptr */
			uint16_t ptr;
			if (sldns_buffer_remaining(pkt) < 1)
				return 0;
			ptr = PTR_OFFSET(labellen, sldns_buffer_read_u8(pkt));
			if (ptrcount++ > MAX_COMPRESS_PTRS)
				return 0; /* loop! */
			if (sldns_buffer_limit(pkt) <= ptr)
				return 0; /* out of bounds! */
			if (!endpos)
				endpos = sldns_buffer_position(pkt);
			sldns_buffer_set_position(pkt, ptr);
		} else {
			/* label contents */
			if (labellen > 0x3f)
				return 0; /* label too long */
			len += 1 + labellen;
			if (len > LDNS_MAX_DOMAINLEN)
				return 0;
			if (labellen == 0) {
				/* end of dname */
				break;
			}
			if (sldns_buffer_remaining(pkt) < labellen)
				return 0;
			sldns_buffer_skip(pkt, (ssize_t) labellen);
		}
	}
	if (endpos)
		sldns_buffer_set_position(pkt, endpos);

	return sldns_buffer_position(pkt) - pos;
}

/** skip rr ttl and rdata */
int skip_ttl_rdata(sldns_buffer *pkt) {
	uint16_t rdatalen;
	if (sldns_buffer_remaining(pkt) < 6) /* ttl + rdatalen */
		return 0;
	sldns_buffer_skip(pkt, 4); /* ttl */
	rdatalen = sldns_buffer_read_u16(pkt);
	if (sldns_buffer_remaining(pkt) < rdatalen)
		return 0;
	sldns_buffer_skip(pkt, (ssize_t) rdatalen);
	return 1;
}

/** skip RR in packet */
int skip_pkt_rr(sldns_buffer *pkt) {
	if (sldns_buffer_remaining(pkt) < 1)
		return 0;
	if (!pkt_dname_len(pkt))
		return 0;
	if (sldns_buffer_remaining(pkt) < 4)
		return 0;
	sldns_buffer_skip(pkt, 4); /* type and class */
	if (!skip_ttl_rdata(pkt))
		return 0;
	return 1;
}

/** skip RRs from packet */
int skip_pkt_rrs(sldns_buffer *pkt, int num) {
	int i;
	for (i = 0; i < num; i++) {
		if (!skip_pkt_rr(pkt))
			return 0;
	}
	return 1;
}

/** skip RR in packet */
int skip_pkt_request_rr(sldns_buffer *pkt) {
	if (sldns_buffer_remaining(pkt) < 1)
		return 0;
	if (!pkt_dname_len(pkt))
		return 0;
	if (sldns_buffer_remaining(pkt) < 4)
		return 0;
	sldns_buffer_skip(pkt, 4); /* type and class */
	return 1;
}

int dname_pkt_copy(sldns_buffer *pkt, uint8_t *to, uint8_t *dname) {
	/* copy over the dname and decompress it at the same time */
	size_t comprcount = 0;
	size_t len = 0;
	uint8_t lablen;
	uint8_t *start = to;

	lablen = *dname++;
	while (lablen) {
		if (LABEL_IS_PTR(lablen)) {
			if (comprcount++ > MAX_COMPRESS_PTRS) {
				/* too many compression pointers */
				*to = 0; /* end the result prematurely */
				return 0;
			}
			/* follow pointer */
			if ((size_t) PTR_OFFSET(lablen, *dname) >= sldns_buffer_limit(pkt))
				return 0;
			dname = sldns_buffer_at(pkt, PTR_OFFSET(lablen, *dname));
			lablen = *dname++;
			continue;
		}
		if (lablen > LDNS_MAX_LABELLEN) {
			*to = 0; /* end the result prematurely */
			return 0;
		}log_assert(lablen <= LDNS_MAX_LABELLEN);
		len += (size_t) lablen + 1;
		if (len >= LDNS_MAX_DOMAINLEN) {
			*to = 0; /* end the result prematurely */
			log_err("bad dname in dname_pkt_copy");
			return 0;
		}
		*to++ = lablen;
		memmove(to, dname, lablen);
		dname += lablen;
		to += lablen;
		lablen = *dname++;
	}
	/* copy last \0 */
	*to = 0;
	return to > start ? to - start + 1 : 0;
}

/* determine length of a dname in buffer, no compression pointers allowed */
size_t query_dname_len(sldns_buffer *query) {
	size_t len = 0;
	size_t labellen;
	while (1) {
		if (sldns_buffer_remaining(query) < 1)
			return 0; /* parse error, need label len */
		labellen = sldns_buffer_read_u8(query);
		if (labellen & 0xc0)
			return 0; /* no compression allowed in queries */
		len += labellen + 1;
		if (len > LDNS_MAX_DOMAINLEN)
			return 0; /* too long */
		if (labellen == 0)
			return len;
		if (sldns_buffer_remaining(query) < labellen)
			return 0; /* parse error, need content */
		sldns_buffer_skip(query, (ssize_t) labellen);
	}
}

int query_info_parse(struct query_info *m, sldns_buffer *query) {
	uint8_t *q = sldns_buffer_begin(query);
	/* minimum size: header + \0 + qtype + qclass */
	if (sldns_buffer_limit(query) < LDNS_HEADER_SIZE + 5)
		return 0;
	if ((LDNS_OPCODE_WIRE(q) != LDNS_PACKET_QUERY
			&& LDNS_OPCODE_WIRE(q) != LDNS_PACKET_NOTIFY)
			|| LDNS_QDCOUNT(q) != 1 || sldns_buffer_position(query) != 0)
		return 0;
	sldns_buffer_skip(query, LDNS_HEADER_SIZE);
	m->qname = sldns_buffer_current(query);
	if ((m->qname_len = query_dname_len(query)) == 0)
		return 0; /* parse error */
	if (sldns_buffer_remaining(query) < 4)
		return 0; /* need qtype, qclass */
	m->qtype = sldns_buffer_read_u16(query);
	m->qclass = sldns_buffer_read_u16(query);
	// m->local_alias = NULL;
	return 1;
}

