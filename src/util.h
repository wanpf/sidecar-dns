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

#ifndef SRC_UTIL_H_
#define SRC_UTIL_H_

// 红黑树排序比较函数
int cmp_name_type(const void *a, const void *b);

// 获取系统单调递增时间（单位：毫秒）
long long getSteadyMillis();

// 将dns文本记录解析成 resource_record 结构体
resource_record* rrstr2dnsrr(const char *rrstr);

/*
 * 在双向链表的尾部插入元素
 * head：链表首部地址
 * node：新元素
 * 返回值：新元素
 */
template<class T>
inline T* list_insert(T **head, T *node) {
	if (!*head) {
		*head = node->pre = node->succ = node;
	} else {
		node->pre = (*head)->pre;
		(*head)->pre->succ = node;
		node->succ = *head;
		(*head)->pre = node;
	}
	return node;
}

/*
 * 将元素从双向链表中删除
 * head：链表首部地址
 * node：被删除元素
 * 返回值：被删除元素的下一个元素
 */
template<class T>
inline T* list_remove(T **head, T *node) {
	T *next = nullptr;
	if (node->succ == node) {
		*head = nullptr;
	} else {
		next = node->succ;
		if (*head == node) {
			*head = next;
		}
		node->pre->succ = node->succ;
		node->succ->pre = node->pre;
	}
	return next;
}

#endif /* SRC_UTIL_H_ */
