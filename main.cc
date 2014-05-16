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
#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <cstdio>
#include <signal.h>
#include <arpa/inet.h>
#include <map>
#include <pthread.h>
#include <syslog.h>
#include <cstdlib>
#include <pwd.h>
#include <grp.h>
#include "config.h"
#include "packet.h"
#include "strategy.h"
#include "misc.h"
#include "job.h"

#ifdef USE_CAPS
#include <sys/prctl.h>
#include <sys/capability.h>
#endif


using namespace loaded;
using namespace std;

typedef struct {
	int family;
	int qn;
} thread_args;


void die(const char *s)
{
	perror(s);
	exit(errno);
}


void *balance_thread(void *vp)
{
	thread_args *ta = static_cast<thread_args *>(vp);
	do_balance(ta->family, ta->qn);
	return NULL;
}


void *failure_thread(void *vp)
{
	thread_args *ta = static_cast<thread_args *>(vp);
	do_failure_checking(ta->family);
	return NULL;
}


void usage(const char *path)
{
	cout<<"Usage: "<<path<<" [-4|-6] [-c configfile] [-f] [-D] [-Q qlen]\n";
#ifdef USE_CAPS
	cout<<"\t\t[-U user]\n";
#endif
	exit(1);
}


void sigalarm(int x)
{
	return;
}


void close_fds()
{
	struct rlimit rl;

	if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
		die("getrlimit");
	for (unsigned int i = 3; i <= rl.rlim_max; ++i)
		close(i);

	if (!Config::debug) {
		close(0);
		open("/dev/null", O_RDWR);
		dup2(0, 1);
	}
}


int main(int argc, char **argv)
{
	string config = "loaded.config";
	int i = 0, af = AF_INET;

	while ((i = getopt(argc, argv, "f46c:DQ:U:")) != -1) {
		switch (i) {
		case '4':
			af = AF_INET;
			break;
		case '6':
			af = AF_INET6;
			break;
		case 'c':
			config = optarg;
			break;
		case 'f':
			Config::failover = 1;
			break;
		case 'D':
			Config::debug = 1;
			break;
		case 'Q':
			Config::nfq_len = atoi(optarg);
			break;
		case 'U':
			Config::user = optarg;
			break;
		default:
			usage(argv[0]);
		}
	}

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigalarm;

	if (sigaction(SIGALRM, &sa, NULL) < 0 || sigaction(SIGPIPE, &sa, NULL) < 0)
		;

	strategy_init();
	parse_config(config);

	close_fds();
	openlog("loaded", LOG_PID, LOG_DAEMON);

	nice(-20);

	int qn = balance_cpus();

	struct passwd *pw = getpwnam(Config::user.c_str());
	if (!pw)
		die("unknown user:getpwnam");

	if (chroot("/var/run/empty") < 0)
		die("chroot");
	chdir("/");

#ifdef USE_CAPS

	if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0)
		die("prctl");

	if (setgid(pw->pw_gid) < 0)
		die("setgid");
	if (initgroups(Config::user.c_str(), pw->pw_gid) < 0)
		die("initgroups");
	if (setuid(pw->pw_uid) < 0)
		die("setuid");

	cap_t my_caps;
	cap_value_t cv[2] = {CAP_NET_ADMIN, CAP_NET_RAW};

	if ((my_caps = cap_init()) == NULL)
		die("cap_init");
	if (cap_set_flag(my_caps, CAP_EFFECTIVE, 2, cv, CAP_SET) < 0)
		die("cap_set_flag");
	if (cap_set_flag(my_caps, CAP_PERMITTED, 2, cv, CAP_SET) < 0)
		die("cap_set_flag");
	if (cap_set_proc(my_caps) < 0)
		die("cap_set_proc");
	cap_free(my_caps);
#endif

	if (!Config::debug) {
		if (fork() > 0) {
			exit(1);
		}
	} else {
		// Now, kill stderr too
		dup2(0, 2);
	}

	syslog(LOG_DAEMON, "started");

	if (!Config::debug) {
		if (qn == 0)
			setsid();
	}

	pthread_t tid1, tid2;
	thread_args ta = {af, qn};
	pthread_create(&tid1, NULL, balance_thread, &ta);

	if (Config::failover)
		pthread_create(&tid2, NULL, failure_thread, &af);

	void *vp = NULL;
	pthread_join(tid1, &vp);

	if (Config::failover)
		pthread_join(tid2, &vp);

	syslog(LOG_DAEMON, "exiting");
	return 0;
}

