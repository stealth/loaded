/*
 * Copyright (C) 2003-2014 Sebastian Krahmer.
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
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <cerrno>
#include <iostream>
#include <unistd.h>
#include <cstdio>
#include <pthread.h>
#include <stdint.h>
#include "packet.h"
#include "misc.h"
#include "strategy.h"
#include "config.h"


namespace loaded {

using namespace std;


loaded::ipq_packet_msg_t *packet_queue::pm = NULL;
struct nfqnl_msg_packet_hdr *packet_queue::ph = NULL;
int packet_queue::q_count = 0;
string packet_queue::err = "";


int packet_queue::fix_ipv4(const sockaddr *saddr)
{
	iphdr *iph = NULL;
	tcphdr *tcph = NULL;
	udphdr *udph = NULL;
	uint32_t oval = 0, nval = 0;

	iph = (iphdr *)pm->payload;
	size_t p_len = pm->data_len;

	if (destination == DESTINATION_BACKEND) {
		oval = iph->daddr;
		iph->daddr = ((sockaddr_in*)saddr)->sin_addr.s_addr;
		nval = iph->daddr;
	} else {
		oval = iph->saddr;
		iph->saddr = Config::VIP4.sin_addr.s_addr;
		nval = iph->saddr;
	}

	switch (iph->protocol) {
	case IPPROTO_TCP:
		if (p_len < (size_t)(iph->ihl<<2) + sizeof(tcphdr))
			return -1;
		if ((ntohs(iph->frag_off) & 0x1fff) == 0) {
			tcph = (struct tcphdr*)(pm->payload + (iph->ihl<<2));
			tcph->th_sum = cksum_update_32(oval, nval, tcph->th_sum);
		}
		break;
	case IPPROTO_UDP:
		if (p_len < (size_t)(iph->ihl<<2) + sizeof(udphdr))
			return -1;
		if ((ntohs(iph->frag_off) & 0x1fff) == 0) {
			udph = (struct udphdr*)(pm->payload + (iph->ihl<<2));
			udph->uh_sum = cksum_update_32(oval, nval, udph->uh_sum);
		}
		break;
	case IPPROTO_ICMP:

		// No checksum recalculation needed
		break;
	default:
		return -1;
	}

	iph->check = cksum_update_32(oval, nval, iph->check);

	return 0;
}


int packet_queue::fix_ipv6(const sockaddr *saddr)
{

	ip6_hdr *ip6h = (ip6_hdr*)pm->payload;
	unsigned char nxt = ip6h->ip6_nxt;
	unsigned char *ptr = pm->payload + sizeof(ip6_hdr);
	unsigned char *end_ptr = pm->payload + pm->data_len;
	uint32_t oval[4], nval[4];

	if (destination == DESTINATION_BACKEND) {
		memcpy(&oval, &ip6h->ip6_dst.s6_addr32, 16);
		ip6h->ip6_dst = ((struct sockaddr_in6*)saddr)->sin6_addr;
		memcpy(&nval, &ip6h->ip6_dst.s6_addr32, 16);
	} else {
		memcpy(&oval, &ip6h->ip6_src.s6_addr32, 16);
		ip6h->ip6_src = Config::VIP6.sin6_addr;
		memcpy(&nval, &ip6h->ip6_src.s6_addr32, 16);
	}

	while (ptr < end_ptr) {
		if (nxt == IPPROTO_TCP ||
		    nxt == IPPROTO_ICMPV6 ||
		    nxt == IPPROTO_UDP)
			break;
		nxt = *ptr;
		ptr += ptr[1];
	}

//XXX check for frags?

	if (ptr >= end_ptr)
		return -1;

	icmp6_hdr *icmp6h = NULL;
	tcphdr *tcph = NULL;
	udphdr *udph = NULL;

	switch (nxt) {
	case IPPROTO_TCP:
		if (ptr + sizeof(tcphdr) > end_ptr)
			return -1;
		tcph = (tcphdr*)ptr;
		tcph->th_sum = cksum_update_128(oval, nval, tcph->th_sum);
		break;
	case IPPROTO_UDP:
		if (ptr + sizeof(udphdr) > end_ptr)
			return -1;
		udph = (udphdr*)ptr;
		udph->uh_sum = cksum_update_128(oval, nval, udph->uh_sum);
		break;
	case IPPROTO_ICMPV6:
		if (ptr + sizeof(icmp6_hdr) > end_ptr)
			return -1;
		icmp6h = (icmp6_hdr*)ptr;
		icmp6h->icmp6_cksum = cksum_update_128(oval, nval, icmp6h->icmp6_cksum);
		break;
	default:
		return -1;
	}

	return 0;
}


#ifdef USE_NETFILTERQUEUE

int packet_queue::nfqueue_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                       struct nfq_data *nfa, void *data)
{
	ph = nfq_get_msg_packet_hdr(nfa);

	if (!ph) {
		err = "packet_queue::nfqueue_cb::nfq_get_msg_packet_hdr:";
		err += strerror(errno);
		return -1;
	}

	if ((pm->data_len = nfq_get_payload(nfa, &pm->payload)) < 0) {
		err = "packet_queue::nfqueue_cb::nfq_get_payload:";
		err += strerror(errno);
		return -1;
	}

	return 0;

}



int packet_queue::init(int af)
{
	if ((h = nfq_open()) == NULL) {
		err = "packet_queue::init::nfq_open:";
		err += strerror(errno);
		return -1;
	}

	if (nfq_unbind_pf(h, af) < 0) {
		err = "packet_queue::init::nfq_unbind_pf:";
		err += strerror(errno);
		return -1;
	}
	if (nfq_bind_pf(h, af) < 0) {
		err = "packet_queue::init::nfq_bind_pf:";
		err += strerror(errno);
		return -1;
	}


	if ((qh = nfq_create_queue(h, q_num, &nfqueue_cb, NULL)) == NULL) {
		err = "packet_queue::init::nfq_create_queue:";
		err += strerror(errno);
		return -1;
	}

        if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
                err = "packet_queue::init:can't set packet_copy mode";
                return -1;
        }

	if (nfq_set_queue_maxlen(qh, Config::nfq_len) < 0) {
		err = "packet_queue::init::nfq_set_queue_maxlen:";
		return -1;
	}

	nh = nfq_nfnlh(h);
	fd = nfnl_fd(nh);

	if (Config::strategy == "weighted") {
		choose_ip4 = choose_ip4_weighted;
		choose_ip6 = choose_ip6_weighted;
	} else if (Config::strategy == "rr") {
		choose_ip4 = choose_ip4_rr;
		choose_ip6 = choose_ip6_rr;
	}

	return 0;
}


int packet_queue::recv()
{
	ssize_t n = ::recv(fd, d_packet, sizeof(d_packet), 0);
	if (n <= 0) {
		err = "packet_queue::recv::recv:";
		err += strerror(errno);
		return -1;
	}

	return nfq_handle_packet(h, (char *)d_packet, (int)n);
}

#else


int packet_queue::init(int af)
{
	if ((h = ipq_create_handle(0, af)) == NULL) {
		err = "packet_queue::init::ipq_create_handle:";
		err += strerror(errno);
		return -1;
	}
	if (ipq_set_mode(h, IPQ_COPY_PACKET, MTU) < 0) {
		err = "packet_queue::init::ipq_set_mode";
		err += strerror(errno);
		return -1;
	}

	if (Config::strategy == "weighted") {
		choose_ip4 = choose_ip4_weighted;
		choose_ip6 = choose_ip6_weighted;
	} else if (Config::strategy == "rr") {
		choose_ip4 = choose_ip4_rr;
		choose_ip6 = choose_ip6_rr;
	}

	return 0;
}


int packet_queue::recv()
{
	if ((ipq_read(h, d_packet, MTU, 0)) < 0) {
		err = "packet_queue::recv::ipq_read";
		err += ipq_get_msgerr(d_packet);
		if (errno)
			err += strerror(errno);
		return -1;
	}

	switch (ipq_message_type(packet)) {
	case NLMSG_ERROR:
		err = "Received error message ";
		err += ipq_get_msgerr(d_packet);
		return -1;
	case IPQM_PACKET:
		pm = ipq_get_packet(d_packet);
		break;
	default:
		err = "Unknown error.";
		return -1;
	}

	return 0;
}

#endif

int packet_queue::send(const sockaddr *saddr, int af)
{

	// Every packet that is processed here, must have a valid
	// backend (saddr) assigned to it. If the balance() failed,
	// check that before and do not call send()!

	if (af == AF_INET) {
		if (fix_ipv4(saddr) < 0) {
			err = "packet_queue::send::fix_ipv4: short packet or unknown proto.";
			return -1;
		}
	} else if (af == AF_INET6) {
		if (fix_ipv6(saddr) < 0) {
			err = "packet_queue::send::fix_ipv6: short packet or unknown proto.";
			return -1;
		}
	} else {
		err = "packet_queue::send: Unknown protocol (neither IPv4 nor IPv6).";
		return -1;
	}

#ifdef USE_NETFILTERQUEUE
	if (nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pm->data_len, pm->payload) < 0) {
		err = "packet_queue::send::nfq_set_verdict:";
		err += strerror(errno);
		return -1;
	}
#else
	if (ipq_set_verdict(h, pm->packet_id, NF_ACCEPT, pm->data_len,
	                    pm->payload) < 0) {
		err = "packet_queue::send::ipq_set_verdict";
		err += strerror(errno);
		return -1;
	}
#endif
	return 0;
}


int packet_queue::balance(sockaddr_in &sin, sockaddr_in6 &sin6, int af)
{
	if (af == AF_INET) {
		iphdr *iph = (iphdr*)pm->payload;

		// We dont need to balance if it isnt
		// for the virtual IP. Then it must be from
		// the backends flying home! fix_ip function will notice
		// this
		if (iph->daddr != Config::VIP4.sin_addr.s_addr) {
			destination = DESTINATION_HOME;
			return 0;
		}

		destination = DESTINATION_BACKEND;

		sockaddr_in s;
		// Now, look at the source of the packet ...
		memset(&s, 0, sizeof(s));
		s.sin_addr.s_addr = iph->saddr;

		if (Config::failover)
			pthread_rwlock_rdlock(&VConn4_lock);
		// ... if we already chose an IP for it, use it
		if (VConn4->find(s) != VConn4->end()) {
			sin = VConn4->find(s)->second;
			if (Config::failover)
				pthread_rwlock_unlock(&VConn4_lock);
			return 0;
		}
		if (Config::failover)
			pthread_rwlock_unlock(&VConn4_lock);

		sin = choose_ip4();

		if (Config::failover)
			pthread_rwlock_wrlock(&VConn4_lock);
		VConn4->insert(make_pair(s, sin));
		if (Config::failover)
			pthread_rwlock_unlock(&VConn4_lock);
		return 0;
	} else if (af == AF_INET6) {
		ip6_hdr *ip6h = (ip6_hdr*)pm->payload;

		if (memcmp(&ip6h->ip6_dst, &Config::VIP6.sin6_addr,
		           sizeof(in6_addr)) != 0) {
			destination = DESTINATION_HOME;
			return 0;
		}

		destination = DESTINATION_BACKEND;

		sockaddr_in6 s;
		memset(&s, 0, sizeof(s));
		s.sin6_addr = ip6h->ip6_src;

		if (Config::failover)
			pthread_rwlock_rdlock(&VConn6_lock);
		if (VConn6->find(s) != VConn6->end()) {
			sin6 = VConn6->find(s)->second;
			if (Config::failover)
				pthread_rwlock_unlock(&VConn6_lock);
			return 0;
		}

		if (Config::failover)
			pthread_rwlock_unlock(&VConn6_lock);
		sin6 = choose_ip6();

		if (Config::failover)
			pthread_rwlock_wrlock(&VConn6_lock);
		VConn6->insert(make_pair(s, sin6));
		if (Config::failover)
			pthread_rwlock_unlock(&VConn6_lock);

	} else {
		err = "packet_queue::balance:: Invalid adress family (neither AF_INET nor AF_INET6).";
		return -1;
	}
	return 0;
}

}

