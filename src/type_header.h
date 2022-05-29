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

#ifndef _TYPE_HEADER_H_
#define _TYPE_HEADER_H_

#include <time.h>
#include <ctype.h>
#include <strings.h>

// 扩展DNS包长度
#define EDNS_ADVERTISED_SIZE (4096)

// 单个类别最多允许10条（负载均衡）记录
#define MAX_RR_DATA_SIZE (10)

// TYPE（2字节）+ CLASS（2字节）
#define TYPE_CLASS_LEN (4)

// DNS查询报文头12个字节 + TYPE（2字节）+ CLASS（2字节）
#define QUERY_FIXED_SIZE (16)

// TYPE(2) + CLASS(2) + TTL(4) + LEN(2)
#define TYPE_CLASS_TTL_LEN (10)

// 限定域名长度
#define MAX_NAME_LEN (NORMAL_UDP_SIZE - sizeof(resource_meta))

// 计算成员name_type在cache_data结构体的偏移量（用于红黑树Key转换）
#define CACHE_NAME_OFFSET ((size_t) & (((cache_data *)0)->name_type))

// 计算成员request_data在request_task结构体的偏移量（用于红黑树Key转换）
#define DNS_HDRDAT_OFFSET ((size_t) & (((request_task *)0)->dns_hdrdat) + (size_t) & (((dns_hdr_dat *)0)->request_data))

#pragma pack(push)
#pragma pack(1)

/*
 * 定义DNS Resource Record（资源记录）中域名后面的数据
 */
typedef struct resource_meta {
	uint16_t type;		  // TYPE：A、MX 等
	uint16_t clazz;		  // CLASS: IN
	uint32_t ttl;		  // TTL
	uint16_t resp_len;	  // 应答资源长度
	uint8_t resp_data[1]; // 应答资源数据（长度不定）
} resource_meta;

#pragma pack(pop)

/*
 * 用于缓存的DNS Resource Record 结构体
 */
typedef struct resource_record {
	resource_record *pre;  // 双向链表前驱
	resource_record *succ; // 双向链表后继
	uint8_t is_local;	   // 标记DNS记录，1:本地配置的DNS记录，0:上游DNS记录
	uint8_t is_refuse;	   // 拒绝标记，屏蔽DNS解析
	time_t timestamp;	   // 资源记录的时间戳
	uint32_t ttl_original; // 资源记录的TTL值
	uint32_t ttl_position; // TTL衰减游标
	uint32_t length;	   // 应答资源记录的长度
	uint16_t name_len;	   // 查询域名的长度
	uint16_t cname_len;	   // CNAME别名域名的长度
	resource_meta *meta;   // 资源记录数据，指针执行 name[1] 域名的尾部
	uint8_t name[1];	   // DNS查询域名
} resource_record;

/*
 * 定义缓存结构体
 */
typedef struct cache_data {
	uint8_t index;								// 负载均衡索引记录，用来动态调整应答资源记录的顺序
	uint8_t count;								// 资源记录的数量，比如：一个A记录对应多个 IPv4地址
	resource_record *rr_data[MAX_RR_DATA_SIZE]; // 保存多个资源记录的数组

	uint16_t name_len;	  // 查询的域名长度
	uint16_t type;		  // DNS TYPE
	uint16_t clazz;		  // DNS CLASS
	uint8_t name_type[1]; // 存储查询域名和TYPE（长度不定），用作红黑树的Key
} cache_data;

#pragma pack(push)
#pragma pack(1)

/*
 * DNS 报文头定义
 */
typedef struct dns_hdr_dat {
	uint16_t id;			 // 查询ID
	uint16_t qr :1;		 // 0:请求报文，1:应答报文
	uint16_t opcode :4;	 // 操作码
	uint16_t aa :1;		 // 权威应答
	uint16_t tc :1;		 // 报文超长截断标识
	uint16_t rd :1;		 // 请求递归查询
	uint16_t ra :1;		 // 递归查询可用
	uint16_t zero :3;		 // 保留
	uint16_t rcode :4;		 // 返回码
	uint16_t qcount;		 // 请求记录数
	uint16_t ancount;		 // 应答记录数
	uint16_t nscount;		 // Name Server 记录数
	uint16_t adcount;		 // 附加记录数
	uint8_t request_data[1]; // 请求数据（查询域名）开始地址
} dns_hdr_dat;

#pragma pack(pop)

/*
 * DNS查询客户端结构体
 */
typedef struct request_client {
	struct request_client *pre;	 // 双向链表前驱
	struct request_client *succ; // 双向链表后继

	time_t timestamp;			   // 创建时间戳
	socklen_t clientlen;		   // 客户端网络地址长度
	struct sockaddr_in clientaddr; // 客户端网络地址（用于异步发送消息）

	uint8_t *name;	   // 查询域名，指向 dns_hdrdat.request_data
	uint16_t name_len; // 查询域名的长度
	uint16_t type;	   // 查询类别

	dns_hdr_dat dns_hdrdat; // DNS查询报文
} request_client;

/*
 * DNS查询任务结构体，不同的客户端相同的查询对应一个任务
 */
typedef struct request_task {
	struct request_task *pre;  // 双向链表前驱
	struct request_task *succ; // 双向链表后继

	request_client *client_list; // 客户端链表头
	uint64_t clock_millisecond;	 // 单调递增时间（单位：毫秒）

	uint8_t *name;	   // 查询域名
	uint16_t name_len; // 查询域名长度
	uint16_t type;	   // 查询类别

	int sent_count;			// 发给上游DNS服务器次数（单个请求发送次数）
	int buffer_size;		// 给结构体分配的buffer长度
	int request_length;		// 发送给上游DNS服务器的请求报文长度
	dns_hdr_dat dns_hdrdat; // DNS报文数据
} request_task;

#endif /* _TYPE_HEADER_H_ */
