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
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <iostream>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <cstdio>
#include <cerrno>
#include <list>
#include <map>
#include "packet.h"
#include "lock.h"
#include "strategy.h"
#include "config.h"



using namespace std;

namespace loaded {


int do_balance(int af, int qn)
{
	packet_queue *pq = new packet_queue(qn);
	sockaddr_in b4;
	sockaddr_in6 b6;

	// The nfq code inside the ->init() shares the nf_queue system
	// wide netlink ressource and is therefore racy. So we need a lock
	// in case we run on multiple cores
	sock_lock *sl = new sock_lock("loaded.lck");
	sl->lock();

	if (pq->init(af) < 0) {
		syslog(LOG_ERR, "%s", pq->why());
		delete pq;
		return -1;
	}

	delete sl;

	for (;;) {
		if (pq->recv() < 0) {
			syslog(LOG_ERR, "%s", pq->why());
			continue;
		}
		if (pq->balance(b4, b6, af) < 0) {
			syslog(LOG_ERR, "%s", pq->why());
			continue;
		}

		if (af == AF_INET) {
			if (pq->send((sockaddr *)&b4, af) < 0)
				syslog(LOG_ERR, "%s", pq->why());;
		} else if (af == AF_INET6) {
			if (pq->send((sockaddr *)&b6, af) < 0)
				syslog(LOG_ERR, "%s", pq->why());;
		}
	}
	delete pq;
	return 0;
}


void do_failure_checking4()
{
	struct icmphdr icmph;
	memset(&icmph, 0, sizeof(icmph));
	sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_port = htons(IPPROTO_ICMP);
	sin.sin_family = AF_INET;

	if (inet_pton(AF_INET, Config::broadcast.c_str(), &sin.sin_addr) < 0) {
		syslog(LOG_ERR, "do_failure_checking4::inet_pton: weird broadcast address");
		return;
	}

	int raw_sock = 0;
	if ((raw_sock = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
		syslog(LOG_ERR, "do_failure_checking4::socket");
		return;
	}

	int one = 1;
	if (setsockopt(raw_sock, SOL_SOCKET, SO_BROADCAST, &one,
	               sizeof(one)) < 0) {
		syslog(LOG_ERR, "do_failure_checking4::setsockopt");
		return;
	}

	icmph.type = ICMP_ECHO;
	icmph.code = 0;

	// id is used to detect potential races between multiple cores
	unsigned int id = getpid();
	unsigned char buf[2048];
	for (;;) {
		sleep(Config::check_cycle);

		icmph.un.echo.id = id;
		icmph.checksum = 0;
		icmph.checksum = in_cksum((unsigned short*)&icmph,
		                          sizeof(icmph));
		if (sendto(raw_sock, &icmph, sizeof(icmph), 0,
			   (struct sockaddr *)&sin, sizeof(sin)) < 0) {
			syslog(LOG_ERR, "do_failure_checking4::send");
			continue;
		}

		fd_set rset;
		int n = 0;
		struct icmphdr *icmphp = NULL;
		list<sockaddr_in> hosts_icmp_alive;

		// Look which hosts are 'pingable'
		for (;;) {
			FD_ZERO(&rset);
			FD_SET(raw_sock, &rset);
			timeval tv;
			tv.tv_sec = 3;
			tv.tv_usec = 0;
			n = select(raw_sock + 1, &rset, NULL, NULL, &tv);
			if (n < 0 && errno == EINTR)
				continue;
			if (n < 0) {
				syslog(LOG_ERR, "do_failure_checking4::select");
				return;
			}

			// timeout
			if (n == 0)
				break;

			sockaddr_in from;
			socklen_t flen = sizeof(from);
			n = recvfrom(raw_sock, buf, sizeof(buf), 0,
			             (sockaddr*)&from, &flen);
			if (n < 0) {
				syslog(LOG_ERR, "do_failure_checking4::recvfrom");
				continue;
			}
			iphdr *iph = (iphdr*)buf;

			// not a complete packet?
			if ((size_t)n < (iph->ihl<<2) + sizeof(icmphdr))
				continue;
			icmphp = (icmphdr*)(((char*)iph)+(iph->ihl<<2));

			// wrong ID or not a reply -> ignore
			if (icmphp->un.echo.id != id || icmphp->type != ICMP_ECHOREPLY)
				continue;
			from.sin_port = 0;
			from.sin_family = 0;
			hosts_icmp_alive.push_back(from);
		}

		int tcp_sock = 0;
		list<sockaddr_in>::iterator i = hosts_icmp_alive.begin();
		map<sockaddr_in, uint32_t, sockaddrLess> hosts_tcp_alive;
		sockaddr_in sin2;

		// Look which hosts run certain service
		for (; i != hosts_icmp_alive.end(); ++i) {
			if ((tcp_sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
				syslog(LOG_ERR, "do_failure_checking4::socket");
				return;
			}
			struct itimerval it1 = {{2, 0}, {0, 0}},
			                 it2 = {{0, 0}, {0, 0}};
			setitimer(ITIMER_REAL, &it1, NULL);
			sin2 = *i;
			sin2.sin_port = htons(Config::port_alive);
			sin2.sin_family = AF_INET;
			if (connect(tcp_sock, (sockaddr*)&sin2, sizeof(sin2)) >= 0){
				// maybe add read()/write() here too
				hosts_tcp_alive[sin2] = 1;
			}
			setitimer(ITIMER_REAL, &it2, NULL);
			close(tcp_sock);
		}


		// migrate the old virtual connection map
		map<sockaddr_in, sockaddr_in, sockaddrLess> *new_VConn4 = NULL;
		new_VConn4 = new map<sockaddr_in, sockaddr_in, sockaddrLess>;

		pthread_rwlock_rdlock(&VConn4_lock);
		map<sockaddr_in, sockaddr_in, sockaddrLess>::iterator k = VConn4->begin();
		for (;k != VConn4->end(); ++k) {
			if (hosts_tcp_alive.find(k->second) != hosts_tcp_alive.end()) {
				new_VConn4->insert(make_pair(k->first, k->second));
			}
		}
		pthread_rwlock_unlock(&VConn4_lock);

		pthread_rwlock_wrlock(&VConn4_lock);
		delete VConn4;
		VConn4 = new_VConn4;

#ifdef FAILOVER_DEBUG
		char dst[128], src[128];
		cerr<<"VConn4:\n";
		for (k = VConn4->begin(); k != VConn4->end(); ++k) {
			cerr<<inet_ntop(AF_INET, &k->first.sin_addr, src, sizeof(src))
		            <<"->"
			    <<inet_ntop(AF_INET, &k->second.sin_addr, dst, sizeof(dst))
			    <<endl;
		}
#endif
		pthread_rwlock_unlock(&VConn4_lock);

		map<sockaddr_in, uint32_t, sockaddrLess>::iterator j;

		// construct a new RR list from the living TCP hosts
		vector<sockaddr_in> *new_rr4 = new vector<sockaddr_in>;

		for (j = hosts_tcp_alive.begin(); j != hosts_tcp_alive.end(); ++j) {
			new_rr4->push_back(j->first);
		}

		pthread_rwlock_wrlock(&rr4_lock);
		delete rr4;
		rr4 = new_rr4;
		pthread_rwlock_unlock(&rr4_lock);
	}
	return;
}


void do_failure_checking6()
{
	for (;;)
		sleep(Config::check_cycle);
}


int do_failure_checking(int af)
{
	if (af == AF_INET)
		do_failure_checking4();
	else
		do_failure_checking6();

	return 0;
}

} // namespace loaded

