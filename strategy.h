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
#ifndef __strategy_h__
#define __strategy_h__

#include <netinet/in.h>
#include <map>
#include <vector>
#include <pthread.h>
#include "packet.h"


namespace loaded {

extern std::map<sockaddr_in, sockaddr_in, sockaddrLess> *VConn4;
extern std::map<sockaddr_in6, sockaddr_in6, sockaddrLess6> *VConn6;

extern pthread_rwlock_t VConn4_lock;
extern pthread_rwlock_t VConn6_lock;

extern sockaddr_in the_backend4;
extern sockaddr_in6 the_backend6;

extern std::vector<sockaddr_in> *rr4;
extern std::vector<sockaddr_in6> *rr6;

extern pthread_rwlock_t rr4_lock;
extern pthread_rwlock_t rr6_lock;

sockaddr_in choose_ip4_weighted();

sockaddr_in choose_ip4_rr();

sockaddr_in6 choose_ip6_weighted();

sockaddr_in6 choose_ip6_rr();

void strategy_init();

}

#endif

