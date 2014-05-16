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
#include <map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <vector>
#include <pthread.h>
#include "config.h"
#include "strategy.h"
#include "misc.h"


using namespace std;

namespace loaded {

//Virtual connections src -> dst
map<sockaddr_in, sockaddr_in, sockaddrLess> *VConn4 = NULL;
map<sockaddr_in6, sockaddr_in6, sockaddrLess6> *VConn6 = NULL;

pthread_rwlock_t VConn4_lock = PTHREAD_RWLOCK_INITIALIZER;
pthread_rwlock_t VConn6_lock = PTHREAD_RWLOCK_INITIALIZER;


sockaddr_in the_backend4;
sockaddr_in6 the_backend6;

vector<sockaddr_in> *rr4 = NULL;
vector<sockaddr_in>::size_type rr4_idx = 0;

vector<sockaddr_in6> *rr6 = NULL;
vector<sockaddr_in6>::size_type rr6_idx = 0;

pthread_rwlock_t rr4_lock = PTHREAD_RWLOCK_INITIALIZER;
pthread_rwlock_t rr6_lock = PTHREAD_RWLOCK_INITIALIZER;


// Choose backend with least connection entries in VConn4 table
sockaddr_in choose_ip4_weighted()
{
	if (Config::failover)
		pthread_rwlock_rdlock(&VConn4_lock);

	sockaddr_in min_addr = the_backend4;
	map<sockaddr_in, uint32_t, sockaddrLess> counts;
	for (map<sockaddr_in, sockaddr_in>::iterator i = VConn4->begin(); i != VConn4->end(); ++i) {
		++counts[i->second];
	}

	if (Config::failover)
		pthread_rwlock_unlock(&VConn4_lock);

	uint32_t min = 0xffffffff;
	for (map<sockaddr_in, uint32_t, sockaddrLess>::iterator i = counts.begin(); i != counts.end(); ++i) {
		if (min > i->second) {
			min = i->second;
			min_addr = i->first;
		}
	}
	return min_addr;
}


sockaddr_in choose_ip4_rr()
{
	sockaddr_in sin;

	if (Config::failover)
		pthread_rwlock_wrlock(&rr4_lock);

	if (rr4->size() == 0)
		sin = the_backend4;
	else {
		rr4_idx = (rr4_idx + 1) % rr4->size();
		sin = (*rr4)[rr4_idx];
	}

	if (Config::failover)
		pthread_rwlock_unlock(&rr4_lock);
	return sin;
}


sockaddr_in6 choose_ip6_weighted()
{
	if (Config::failover)
		pthread_rwlock_rdlock(&VConn6_lock);

	sockaddr_in6 min_addr = the_backend6;
	map<sockaddr_in6, uint32_t, sockaddrLess6> counts;
	for (map<sockaddr_in6, sockaddr_in6>::iterator i = VConn6->begin(); i != VConn6->end(); ++i) {
		++counts[i->second];
	}

	if (Config::failover)
		pthread_rwlock_unlock(&VConn6_lock);

	uint32_t min = 0xffffffff;
	for (map<sockaddr_in6, uint32_t, sockaddrLess6>::iterator i = counts.begin(); i != counts.end(); ++i) {
		if (min > i->second) {
			min = i->second;
			min_addr = i->first;
		}
	}
	return min_addr;
}


sockaddr_in6 choose_ip6_rr()
{
	sockaddr_in6 sin6;

	if (Config::failover)
		pthread_rwlock_wrlock(&rr6_lock);

	if (rr6->size() == 0)
		sin6 = the_backend6;
	else {
		rr6_idx = (rr6_idx + 1) % rr6->size();
		sin6 = (*rr6)[rr6_idx];
	}

	if (Config::failover)
		pthread_rwlock_unlock(&rr6_lock);
	return sin6;
}


void strategy_init()
{
	VConn4 = new map<sockaddr_in, sockaddr_in, sockaddrLess>;
	VConn6 = new map<sockaddr_in6, sockaddr_in6, sockaddrLess6>;
	rr4 = new vector<sockaddr_in>;
	rr6 = new vector<sockaddr_in6>;
}

}

