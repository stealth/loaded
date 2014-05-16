/*
 * Copyright (C) 2011-2014 Sebastian Krahmer.
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

#ifndef __socket_lock_h__
#define __socket_lock_h__

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string>
#include <cstring>
#include <unistd.h>


class sock_lock {

	int sock;

	struct sockaddr_un sun;
public:

	sock_lock(const std::string &sname)
	{
		memset(&sun, 0, sizeof(sun));
		strncpy(&sun.sun_path[1], sname.c_str(), sizeof(sun.sun_path) - 2);
		sun.sun_family = AF_UNIX;

		if ((sock = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0)
			throw "opening lock socket failed";
	}

	// by destroying the object, you will loose the lock
	~sock_lock()
	{
		close(sock);
	}

	void lock(useconds_t us = 20)
	{
		while (bind(sock, (struct sockaddr *)&sun, sizeof(sun)) < 0)
			usleep(us);
	}

	bool try_lock()
	{
		return bind(sock, (struct sockaddr *)&sun, sizeof(sun)) == 0;
	}

	void unlock()
	{
		close(sock);
		if ((sock = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0)
			throw "opening lock socket failed";
	}
};

#endif

