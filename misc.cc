#include <cstdio>
#include <cerrno>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <map>
#include <sched.h>
#include "packet.h"
#include "strategy.h"
#include "config.h"



namespace loaded {

using namespace std;

unsigned short in_cksum (unsigned short *ptr, int nbytes);

uint16_t cksum_update_128(uint32_t oval[4], uint32_t nval[4], uint16_t osum)
{
	u_int16_t sum = 0;
	sum = cksum_update_32(oval[0], nval[0], osum);
	sum = cksum_update_32(oval[1], nval[1], sum);
	sum = cksum_update_32(oval[2], nval[2], sum);
	sum = cksum_update_32(oval[3], nval[3], sum);
	return sum;
}


uint16_t cksum_update_32(uint32_t oval, uint32_t nval, uint16_t osum)
{
	int32_t sum = ~osum;

	sum &= 0xffff;

	sum -= (oval >> 16);
	sum -= (oval & 0xffff);

	sum += (nval >> 16);
	sum += (nval & 0xffff);

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return ~sum;
}


unsigned short
in_cksum (unsigned short *ptr, int nbytes)
{

	register long sum;		/* assumes long == 32 bits */
	u_short oddbyte;
	register u_short answer;	/* assumes u_short == 16 bits */


	/*
	* Our algorithm is simple, using a 32-bit accumulator (sum),
	* we add sequential 16-bit words to it, and at the end, fold back
	* all the carry bits from the top 16 bits into the lower 16 bits.
	*/

	sum = 0;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nbytes == 1) {
		oddbyte = 0;		/* make sure top half is zero */
		*((unsigned char *) & oddbyte) = *(unsigned char *) ptr;	/* one byte only */
		sum += oddbyte;
	}

	/*
	* Add back carry outs from top 16 bits to low 16 bits.
	*/

	sum = (sum >> 16) + (sum & 0xffff);	/* add high-16 to low-16 */
	sum += (sum >> 16);		/* add carry */
	answer = ~sum;		/* ones-complement, then truncate to 16 bits */
	return (answer);
}


int parse_config(const string &path)
{
	FILE *f = fopen(path.c_str(), "r");
	if (!f) {
		fprintf(stderr, "parse_config: Can't open file %s: %s\n",
		        path.c_str(), strerror(errno));
		return -1;
	}

	char buf[1024], *ptr = NULL;
	while (fgets(buf, sizeof(buf), f)) {
		ptr = buf;
		while (*ptr == ' ' || *ptr == '\t')
			++ptr;
		if (*ptr == '#')
			continue;
		if (strncmp(ptr, "server4", 7) == 0) {
			ptr += 8;
			strtok(ptr, " \t\n#");
			memset(&the_backend4, 0, sizeof(the_backend4));
			if (inet_pton(AF_INET, ptr, &the_backend4.sin_addr) < 0) {
				fprintf(stderr, "parse_config::inet_pton: %s",
				        strerror(errno));
				return -1;
			}

			// for RR strategy
			rr4->push_back(the_backend4);
		} if (strncmp(ptr, "server6", 7) == 0) {
			ptr += 8;
			strtok(ptr, " \t\n#");
			memset(&the_backend6, 0, sizeof(the_backend6));
			if (inet_pton(AF_INET6, ptr, &the_backend6.sin6_addr) < 0) {
				fprintf(stderr, "parse_config::inet_pton: %s",
				        strerror(errno));
				return -1;
			}
			rr6->push_back(the_backend6);
		} else if (strncmp(ptr, "VIP4", 4) == 0) {
			ptr += 5;
			strtok(ptr, " \t\n#");
			if (inet_pton(AF_INET,ptr,&Config::VIP4.sin_addr) < 0) {
				fprintf(stderr, "parse_config::inet_pton: %s",
				        strerror(errno));
				return -1;
			}
		} else if (strncmp(ptr, "VIP6", 4) == 0) {
			ptr += 5;
			strtok(ptr, " \t\n#");
			if (inet_pton(AF_INET6, ptr, &Config::VIP6.sin6_addr) < 0) {
				fprintf(stderr, "parse_config::inet_pton: %s",
				        strerror(errno));
				return -1;
			}
		} else if (strncmp(ptr, "strategy", 8) == 0) {
			ptr += 9;
			strtok(ptr, " \t\n#");
			Config::strategy = ptr;
		} else if (strncmp(ptr, "broadcast", 9) == 0) {
			ptr += 10;
			strtok(ptr, " \t\n#");
			Config::broadcast = ptr;
		} else if (strncmp(ptr, "port_alive", 10) == 0) {
			ptr += 11;
			strtok(ptr, " \t\n#");
			Config::port_alive = atoi(ptr);
		} else if (strncmp(ptr, "check_cycle", 11) == 0) {
			ptr += 12;
			strtok(ptr, " \t\n#");
			Config::check_cycle = atoi(ptr);
		} else if (strncmp(ptr, "nfq_len", 7) == 0) {
			ptr += 8;
			strtok(ptr, " \t\n#");
			Config::nfq_len = atoi(ptr);
		} else if (strncmp(ptr, "failover", 8) == 0) {
			Config::failover = 1;
		}
	}
	fclose(f);
	return 0;

}


int get_cores()
{
	int n = 1;
	char buf[256];

	FILE *f = fopen("/proc/cpuinfo", "r");
	if (!f)
		return -1;

	for (;!feof(f);) {
		memset(buf, 0, sizeof(buf));
		if (fgets(buf, sizeof(buf), f) == NULL)
			break;
		if (strstr(buf, "processor"))
			++n;
	}

	fclose(f);
	return n - 1;
}


int balance_cpus()
{
	int i = 0;
	pid_t pid = 0;
	int ncores = get_cores();

	if (ncores <= 1)
		return 0;

	cpu_set_t *cpuset = CPU_ALLOC(ncores);
	if (!cpuset)
		return -1;

	size_t size = CPU_ALLOC_SIZE(ncores);
	CPU_ZERO_S(size, cpuset);
	CPU_SET_S(0, size, cpuset);

	if (sched_setaffinity(getpid(), size, cpuset) < 0) {
		CPU_FREE(cpuset);
		return -1;
	}
	printf("[+] Bound process %d to core 0.\n", getpid());

	for (i = 1; i < ncores; ++i) {
		pid = fork();
		if (pid < 0) {
			CPU_FREE(cpuset);
			return -1;
		} else if (pid > 0)
			continue;
		CPU_ZERO_S(size, cpuset);
		CPU_SET_S(i, size, cpuset);
		if (sched_setaffinity(getpid(), size, cpuset) < 0) {
			CPU_FREE(cpuset);
			return -1;
		}
		printf("[+] Bound process %d to core %d.\n", getpid(), i);
		break;
	}

	CPU_FREE(cpuset);

	// The core number which will also be the queue number
	return i % ncores;
}


} // namespace loaded


