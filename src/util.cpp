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

#include "sldns/config.h"
#include "sldns/log.h"
#include "sldns/misc.h"
#include "sldns/str2wire.h"
#include "type_header.h"

/*
 * 红黑树排序比较函数
 * Key：由域名 + TYPE组成，中间由 '\0' 分割
 */
int cmp_name_type(const void *a, const void *b) {
	const unsigned char *s1 = (const unsigned char*) a;
	const unsigned char *s2 = (const unsigned char*) b;

	// 比较域名大小（'\0'结尾）
	while (*s1 && (*s1 == *s2)) {
		s1++;
		s2++;
	}
	if (*s1 < *s2) {
		return -1;
	}
	if (*s1 > *s2) {
		return 1;
	}
	++s1;
	++s2;
	// 比较TYPE，2个字节长度
	if (*(uint16_t*) s1 < *(uint16_t*) s2) {
		return -1;
	}
	if (*(uint16_t*) s1 > *(uint16_t*) s2) {
		return 1;
	}
	return 0;
}

// 获取系统单调递增时间（单位：毫秒）
long long getSteadyMillis() {
	struct timespec ts { };
	(void) clock_gettime(CLOCK_MONOTONIC, &ts);
	long long milliseconds = (ts.tv_sec * 1000) + (ts.tv_nsec / 1000000);
	return milliseconds;
}

// 将dns文本记录解析成 resource_record 结构体
resource_record* rrstr2dnsrr(const char *rrstr) {
	int length;
	uint8_t *nm;	  // 域名
	size_t nmlen;	  // 域名长度
	time_t ttl = 0;	  // TTL
	uint8_t *rdata;	  // 应答数据
	size_t rdata_len; // 应答数据长度
	uint8_t rr[LDNS_RR_BUF_SIZE];
	uint16_t rrtype = 0, rrclass = 0; // TYPE 和 CLASS
	resource_record *dnsrr;

	if (!rrstr_get_rr_content(rrstr, &nm, &rrtype, &rrclass, &ttl, rr,
			sizeof(rr), &rdata, &rdata_len)) {
		log_err("bad local-data: %s", rrstr);
		return NULL;
	}

	dname_count_size_labels(nm, &nmlen);
	length = nmlen + sizeof(resource_meta) + rdata_len;
	if (nmlen > LDNS_MAX_DOMAINLEN || length > NORMAL_UDP_SIZE) {
		log_err("too long: %s", rrstr);
		free(nm);
		return NULL;
	}

	dnsrr = (resource_record*) malloc(sizeof(resource_record) + length);
	if (!dnsrr) {
		log_err("malloc failed: %s", rrstr);
		free(nm);
		return NULL;
	}

	memcpy(dnsrr->name, nm, nmlen);
	dnsrr->meta = (resource_meta*) (dnsrr->name + nmlen);
	dnsrr->meta->type = htons(rrtype);
	dnsrr->meta->clazz = htons(rrclass);
	dnsrr->meta->ttl = htonl(ttl);
	dnsrr->meta->resp_len = htons(rdata_len);
	memcpy(dnsrr->meta->resp_data, rdata, rdata_len);
	dnsrr->name_len = nmlen;
	dnsrr->length = length - sizeof(dnsrr->meta->resp_data);
	dnsrr->timestamp = (time_t) time(NULL);
	dnsrr->ttl_original = ttl;
	dnsrr->is_local = true;

	free(nm);

	return dnsrr;
}
