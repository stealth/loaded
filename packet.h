/*
 * Copyright (C) 2003-2011 Sebastian Krahmer.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Sebastian Krahmer.
 * 4. The name Sebastian Krahmer may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef __packet_h__
#define __packet_h__

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string>
#include <map>

extern "C" {
#include <linux/netfilter.h>
#ifdef USE_NETFILTERQUEUE
#include <libnetfilter_queue/libnetfilter_queue.h>
#else
#include <libnetfilter_queue/libipq.h>
#endif
#include <pthread.h>
}

#include <cstring>
#include "misc.h"

namespace loaded {

#define MTU 66000

struct sockaddrLess
{
	bool operator()(sockaddr_in s1, sockaddr_in s2)
	{
		return memcmp(&s1, &s2, sizeof(s1)) < 0;
	}
};


struct sockaddrLess6
{
	bool operator()(sockaddr_in6 s1, sockaddr_in6 s2)
	{
		return memcmp(&s1, &s2, sizeof(s1)) < 0;
	}
};



struct ipq_packet_msg_t {
	unsigned char *payload;
	size_t data_len;
};

class packet_queue {
	unsigned char d_packet[MTU];
#ifdef USE_NETFILTERQUEUE
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	uint16_t q_num;

	// Must be static so the static callback can access it
	static loaded::ipq_packet_msg_t *pm;
	static struct nfqnl_msg_packet_hdr *ph;
#else
	ipq_handle *h;
	::ipq_packet_msg_t *pm;
#endif

	enum { DESTINATION_HOME = 0, DESTINATION_BACKEND} destination;
	static std::string err;
	static int q_count;

	sockaddr_in (*choose_ip4)();

	sockaddr_in6 (*choose_ip6)();

public:

#ifdef USE_NETFILTERQUEUE
	packet_queue(uint16_t q = 0) : h(NULL), qh(NULL), nh(NULL)
	{
		if (++q_count > 1)
			throw "More than one queue active.";
		pm = new loaded::ipq_packet_msg_t;
		q_num = q;
	}
#else

	packet_queue() : h(NULL), pm(NULL), choose_ip4(NULL), choose_ip6(NULL)
	 { }; // TODO: different MTU
#endif

	virtual ~packet_queue()
	{
		if (h)
			nfq_close(h);
	};

	int init(int af);

	const char *why() { return err.c_str(); }

	int recv();

	int balance(sockaddr_in &, sockaddr_in6 &, int af);

	int send(const sockaddr *, int af);

#ifdef USE_NETFILTERQUEUE
	static int nfqueue_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);

#endif

	int fix_ipv4(const sockaddr *);

	int fix_ipv6(const sockaddr *);

};



}

#endif


