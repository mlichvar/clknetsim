/*
 * Copyright (C) 2010  Miroslav Lichvar <mlichvar@redhat.com>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE

/* avoid redirection in glibc headers */
#define adjtimex adjtimex_off
#include <sys/timex.h>
#undef adjtimex

#define fopen fopen_off
#include <stdio.h>
#undef fopen

#include <sys/utsname.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sysmacros.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/un.h>
#include <unistd.h>
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netdb.h>
#include <pwd.h>
#include <stdarg.h>
#include <signal.h>
#include <ifaddrs.h>
#include <linux/types.h>
#include <linux/ethtool.h>
#include <linux/limits.h>
#include <linux/pps.h>
#include <linux/rtc.h>
#include <linux/sockios.h>
#ifdef SO_TIMESTAMPING
#include <linux/ptp_clock.h>
#include <linux/net_tstamp.h>
#endif

#include "protocol.h"

#include "client_fuzz.c"

/* first node in first subnet is 192.168.123.1 */
#define BASE_ADDR 0xc0a87b00
#define NETMASK 0xffffff00
#define NODE_ADDR(subnet, node) (BASE_ADDR + 0x100 * (subnet) + (node) + 1)
#define BROADCAST_ADDR(subnet) (NODE_ADDR(subnet, 0) | 0xff)
#define NODE_FROM_ADDR(addr) (((addr) & ~NETMASK) - 1)
#define SUBNET_FROM_ADDR(addr) ((((addr) & NETMASK) - BASE_ADDR) / 0x100)

#define IP6_NET "\xfc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x23\x00\x00"
#define IS_SIN6_KNOWN(sin6) (memcmp(IP6_NET, &(sin6)->sin6_addr.s6_addr, 14) == 0)
#define NODE_FROM_SIN6(sin6) ((sin6)->sin6_addr.s6_addr[15])
#define SUBNET_FROM_SIN6(sin6) ((sin6)->sin6_addr.s6_addr[14])
#define ADDR_FROM_SIN6(sin6) (BASE_ADDR + (SUBNET_FROM_SIN6(sin6) << 8) + NODE_FROM_SIN6(sin6))

#define PTP_PRIMARY_MCAST_ADDR 0xe0000181 /* 224.0.1.129 */
#define PTP_PDELAY_MCAST_ADDR 0xe000006b /* 224.0.0.107 */
#define PTP_PRIMARY_MCAST_ADDR6 "\xff\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x81"
#define PTP_PDELAY_MCAST_ADDR6 "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x6b"

#define REFCLK_FD 1000
#define REFCLK_ID ((clockid_t)(((unsigned int)~REFCLK_FD << 3) | 3))
#define REFCLK_PHC_INDEX 0
#define SYSCLK_FD 1001
#define SYSCLK_CLOCKID ((clockid_t)(((unsigned int)~SYSCLK_FD << 3) | 3))
#define SYSCLK_PHC_INDEX 1
#define PPS_FD 1002
#define RTC_FD 1003
#define URANDOM_FD 1010
#define UNIX_DIR_FD 1011

#define MAX_SOCKETS 20
#define BASE_SOCKET_FD 100
#define BASE_SOCKET_DEFAULT_PORT 60000

#define MAX_TIMERS 80
#define BASE_TIMER_ID 0xC1230123
#define BASE_TIMER_FD 200

#define URANDOM_FILE (void *)0xD1230123

#if !defined(__GLIBC_PREREQ) || __GLIBC_PREREQ(2, 33)
#define HAVE_STAT
#endif

static FILE *(*_fopen)(const char *path, const char *mode);
static FILE *(*_fdopen)(int fd, const char *mode);
static size_t (*_fread)(void *ptr, size_t size, size_t nmemb, FILE *stream);
static int (*_fileno)(FILE *stream);
static int (*_fclose)(FILE *fp);
static int (*_fcntl)(int fd, int cmd, ...);
#ifdef HAVE_STAT
static int (*_fstat)(int fd, struct stat *statbuf);
static int (*_stat)(const char *pathname, struct stat *statbuf);
#else
static int (*_fxstat)(int ver, int fd, struct stat *statbuf);
static int (*_xstat)(int ver, const char *pathname, struct stat *statbuf);
#endif
static char *(*_realpath)(const char *path, char *resolved_path);
static int (*_mkdir)(const char *pathname, mode_t mode);
static int (*_mkdirat)(int dirfd, const char *pathname, mode_t mode);
static int (*_open)(const char *pathname, int flags, ...);
static ssize_t (*_read)(int fd, void *buf, size_t count);
static int (*_close)(int fd);
static int (*_socket)(int domain, int type, int protocol);
static int (*_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
static ssize_t (*_recvmsg)(int sockfd, struct msghdr *msg, int flags);
static ssize_t (*_send)(int sockfd, const void *buf, size_t len, int flags);
static int (*_usleep)(useconds_t usec);
static void (*_srandom)(unsigned int seed);
static int (*_shmget)(key_t key, size_t size, int shmflg);
static void *(*_shmat)(int shmid, const void *shmaddr, int shmflg);

static unsigned int node;
static int initializing = 0;
static int initialized_symbols = 0;
static int initialized = 0;
static int clknetsim_fd = -1;
static int precision_hack = 1;
static unsigned int random_seed = 0;
static int ip_family = 4;
static int recv_multiply = 1;
static int timestamping = 1;

static double phc_delay = 0.0;
static double phc_jitter = 0.0;
static double phc_jitter_asym = 0.0;
static int phc_jitter_off = 0;
static int phc_jitter_on = 1;
static int phc_swap = 0;

/* Ethernet speed in Mb/s */
static int link_speed = 100000;

static double rtc_offset = 0.0;
static int rtc_timerfd = 0;

enum {
	IFACE_UNIX,
	IFACE_LO,
	IFACE_ALL,
	IFACE_ETH0,
};

struct message {
	char data[MAX_PACKET_SIZE];
	unsigned int len;
	unsigned int subnet;
	unsigned int to_from;
	unsigned int port;
};

struct socket {
	int used;
	int domain;
	int type;
	int port;
	int iface;
	int remote_node;
	int remote_port;
	int listening;
	int connected;
	int broadcast;
	int pkt_info;
	int time_stamping;
	struct message last_ts_msg;
	struct message buffer;
};

static struct socket sockets[MAX_SOCKETS];
static int subnets;
static int unix_subnet = -1;

static double real_time = 0.0;
static double monotonic_time = 0.0;
static double network_time = 0.0;
static double freq_error = 0.0;
static int local_time_valid = 0;

static time_t system_time_offset = 1262304000; /* 2010-01-01 0:00 UTC */

#define TIMER_TYPE_SIGNAL 1
#define TIMER_TYPE_FD 2

struct timer {
	int used;
	int armed;
	int type;
	int fd_flags;
	uint64_t expired;
	clockid_t clock_id;
	double timeout;
	double interval;
};

static struct timer timers[MAX_TIMERS];

static timer_t itimer_real_id;

#define SHM_KEY 0x4e545030
#define SHM_REFCLOCKS 4

static struct shmTime {
  int    mode;
  int    count;
  time_t clockTimeStampSec;
  int    clockTimeStampUSec;
  time_t receiveTimeStampSec;
  int    receiveTimeStampUSec;
  int    leap;
  int    precision;
  int    nsamples;
  int    valid;
  int    clockTimeStampNSec;
  int    receiveTimeStampNSec;
  int    dummy[8]; 
} shm_time[SHM_REFCLOCKS];

static int shm_refclocks = 0;
static double shm_refclock_time = 0.0;
static struct Reply_getrefoffsets refclock_offsets;
static int refclock_offsets_used = 0;
static int pps_fds = 0;

static FILE *pcap = NULL;

static int timer_delete_(timer_t timerid);
static void write_pcap_header(void);

static void make_request(int request_id, const void *request_data, int reqlen, void *reply, int replylen);

static void init_symbols(void) {
	if (initialized_symbols)
		return;

	_fopen = (FILE *(*)(const char *path, const char *mode))dlsym(RTLD_NEXT, "fopen");
	_fdopen = (FILE *(*)(int fd, const char *mode))dlsym(RTLD_NEXT, "fdopen");
	_fread = (size_t (*)(void *ptr, size_t size, size_t nmemb, FILE *stream))dlsym(RTLD_NEXT, "fread");
	_fileno = (int (*)(FILE *stream))dlsym(RTLD_NEXT, "fileno");
	_fclose = (int (*)(FILE *fp))dlsym(RTLD_NEXT, "fclose");
	_fcntl = (int (*)(int fd, int cmd, ...))dlsym(RTLD_NEXT, "fcntl");
#ifdef HAVE_STAT
#if defined(__USE_TIME_BITS64) && __USE_TIME_BITS64 && __TIMESIZE == 32
	_fstat = (int (*)(int fd, struct stat *statbuf))dlsym(RTLD_NEXT, "__fstat64_time64");
	_stat = (int (*)(const char *pathname, struct stat *statbuf))dlsym(RTLD_NEXT, "__stat64_time64");
#else
	_fstat = (int (*)(int fd, struct stat *statbuf))dlsym(RTLD_NEXT, "fstat");
	_stat = (int (*)(const char *pathname, struct stat *statbuf))dlsym(RTLD_NEXT, "stat");
#endif
#else
	_fxstat = (int (*)(int ver, int fd, struct stat *statbuf))dlsym(RTLD_NEXT, "__fxstat");
	_xstat = (int (*)(int ver, const char *pathname, struct stat *statbuf))dlsym(RTLD_NEXT, "__xstat");
#endif
	_realpath = (char *(*)(const char *path, char *resolved_path))dlsym(RTLD_NEXT, "realpath");
	_mkdir = (int (*)(const char *pathname, mode_t mode))dlsym(RTLD_NEXT, "mkdir");
	_mkdirat = (int (*)(int dirfd, const char *pathname, mode_t mode))dlsym(RTLD_NEXT, "mkdirat");
	_open = (int (*)(const char *pathname, int flags, ...))dlsym(RTLD_NEXT, "open");
	_read = (ssize_t (*)(int fd, void *buf, size_t count))dlsym(RTLD_NEXT, "read");
	_close = (int (*)(int fd))dlsym(RTLD_NEXT, "close");
	_socket = (int (*)(int domain, int type, int protocol))dlsym(RTLD_NEXT, "socket");
	_connect = (int (*)(int sockfd, const struct sockaddr *addr, socklen_t addrlen))dlsym(RTLD_NEXT, "connect");
	_recvmsg = (ssize_t (*)(int sockfd, struct msghdr *msg, int flags))dlsym(RTLD_NEXT, "recvmsg");
	_send = (ssize_t (*)(int sockfd, const void *buf, size_t len, int flags))dlsym(RTLD_NEXT, "send");
	_usleep = (int (*)(useconds_t usec))dlsym(RTLD_NEXT, "usleep");
	_srandom = (void (*)(unsigned int seed))dlsym(RTLD_NEXT, "srandom");
	_shmget = (int (*)(key_t key, size_t size, int shmflg))dlsym(RTLD_NEXT, "shmget");
	_shmat = (void *(*)(int shmid, const void *shmaddr, int shmflg))dlsym(RTLD_NEXT, "shmat");

	initialized_symbols = 1;
}

__attribute__((constructor))
static void init(void) {
	unsigned int connect_retries = 100; /* 10 seconds */
	struct sockaddr_un s = {AF_UNIX, "clknetsim.sock"};
	struct Request_register req;
	struct Reply_register rep;
	const char *env;
	char command[64];
	FILE *f;

	if (initializing || initialized)
		return;

	initializing = 1;

	init_symbols();

	env = getenv("CLKNETSIM_START_DATE");
	if (env)
		system_time_offset = atoll(env);

	env = getenv("CLKNETSIM_RANDOM_SEED");
	if (env)
		random_seed = atoi(env);

	env = getenv("CLKNETSIM_IP_FAMILY");
	if (env)
		ip_family = atoi(env);

	env = getenv("CLKNETSIM_RECV_MULTIPLY");
	if (env)
		recv_multiply = atoi(env);

	env = getenv("CLKNETSIM_TIMESTAMPING");
	if (env)
		timestamping = atoi(env);

	env = getenv("CLKNETSIM_LINK_SPEED");
	if (env)
		link_speed = atoi(env);

	env = getenv("CLKNETSIM_PHC_DELAY");
	if (env)
		phc_delay = atof(env);

	env = getenv("CLKNETSIM_PHC_JITTER");
	if (env)
		phc_jitter = atof(env);

	env = getenv("CLKNETSIM_PHC_JITTER_ASYM");
	if (env)
		phc_jitter_asym = atof(env);

	env = getenv("CLKNETSIM_PHC_JITTER_OFF");
	if (env)
		phc_jitter_off = atoi(env);

	env = getenv("CLKNETSIM_PHC_JITTER_ON");
	if (env)
		phc_jitter_on = atoi(env);

	env = getenv("CLKNETSIM_PHC_SWAP");
	if (env)
		phc_swap = atoi(env);

	env = getenv("CLKNETSIM_RTC_OFFSET");
	if (env)
		rtc_offset = atof(env);

	f = _fopen("/proc/self/comm", "r");
	if (f) {
		command[0] = '\0';
		if (!fgets(command, sizeof (command), f))
			;
		fclose(f);

		if (strncmp(command, "valgrind", 8) == 0 ||
		    strncmp(command, "strace", 6) == 0) {
			/* don't connect to the server */
			initialized = 1;
			return;
		}
	}

	env = getenv("CLKNETSIM_PCAP_DUMP");
	if (env) {
		pcap = _fopen(env, "w");
		write_pcap_header();
	}

	if (fuzz_init()) {
		node = 0;
		subnets = 2;
		unix_subnet = 1;
		initialized = 1;
		return;
	}

	env = getenv("CLKNETSIM_NODE");
	if (!env) {
		fprintf(stderr, "clknetsim: CLKNETSIM_NODE variable not set.\n");
		exit(1);
	}
	node = atoi(env) - 1;

	env = getenv("CLKNETSIM_UNIX_SUBNET");
	if (env)
		unix_subnet = atoi(env) - 1;

	env = getenv("CLKNETSIM_SOCKET");
	if (env)
		snprintf(s.sun_path, sizeof (s.sun_path), "%s", env);

	env = getenv("CLKNETSIM_CONNECT_TIMEOUT");
	if (env)
		connect_retries = 10 * atoi(env);

	clknetsim_fd = _socket(AF_UNIX, SOCK_SEQPACKET, 0);

	assert(clknetsim_fd >= 0);

	while (_connect(clknetsim_fd, (struct sockaddr *)&s, sizeof (s)) < 0) {
		if (!--connect_retries) {
			fprintf(stderr, "clknetsim: could not connect to server.\n");
			exit(1);
		}
		_usleep(100000);
	}

	/* this requires the node variable to be already set */
	srandom(0);

	initializing = 0;
	initialized = 1;

	req.node = node;
	make_request(REQ_REGISTER, &req, sizeof (req), &rep, sizeof (rep));

	subnets = rep.subnets;
}

__attribute__((destructor))
static void fini(void) {
	if (initialized)
		make_request(REQ_DEREGISTER, NULL, 0, NULL, 0);

	if (pcap)
		fclose(pcap);

	if (clknetsim_fd >= 0)
		close(clknetsim_fd);
}

static void make_request(int request_id, const void *request_data, int reqlen, void *reply, int replylen) {
	struct Request_packet request;
	int sent, received = 0;

	init();

	if (fuzz_mode) {
		fuzz_process_request(request_id, request_data, reply, replylen);
		return;
	}

	request.header.request = request_id;
	request.header._pad = 0;

	assert(offsetof(struct Request_packet, data) + reqlen <= sizeof (request));

	if (request_data)
		memcpy(&request.data, request_data, reqlen);
	reqlen += offsetof(struct Request_packet, data);

	if ((sent = _send(clknetsim_fd, &request, reqlen, 0)) <= 0 ||
			(reply && (received = recv(clknetsim_fd, reply, replylen, 0)) <= 0)) {
		fprintf(stderr, "clknetsim: server connection closed.\n");
		initialized = 0;
		exit(1);
	}

	assert(sent == reqlen);

	if (!reply)
		return;

	/* check reply length */
	switch (request_id) {
		case REQ_RECV:
			/* reply with variable length */
			assert(received >= offsetof(struct Reply_recv, data));
			assert(offsetof(struct Reply_recv, data) +
				((struct Reply_recv *)reply)->len <= received);
			break;
		case REQ_GETREFOFFSETS:
			/* reply with variable length */
			assert(received >= offsetof(struct Reply_getrefoffsets, offsets));
			assert(offsetof(struct Reply_getrefoffsets, offsets) +
				(sizeof ((struct Reply_getrefoffsets *)reply)->offsets[0]) *
				((struct Reply_getrefoffsets *)reply)->size == received);
			break;
		default:
			assert(received == replylen);
	}
}

static void fetch_time(void) {
	struct Reply_gettime r;

	if (!local_time_valid) {
		make_request(REQ_GETTIME, NULL, 0, &r, sizeof (r));
		real_time = r.real_time;
		monotonic_time = r.monotonic_time;
		network_time = r.network_time;
		freq_error = r.freq_error;
		local_time_valid = 1;
	}
}

static double get_real_time(void) {
	fetch_time();
	return real_time;
}

static double get_monotonic_time(void) {
	fetch_time();
	return monotonic_time;
}

static double get_refclock_offset(void) {
	if (refclock_offsets_used >= refclock_offsets.size) {
		make_request(REQ_GETREFOFFSETS, NULL, 0, &refclock_offsets, sizeof (refclock_offsets));
		assert(refclock_offsets.size > 0);
		refclock_offsets_used = 0;
	}
	return refclock_offsets.offsets[refclock_offsets_used++];
}

static double get_refclock_time(void) {
	fetch_time();
	return network_time - get_refclock_offset();
}

static double get_rtc_time(void) {
	return get_monotonic_time() + rtc_offset;
}

static void settime(double time) {
	struct Request_settime req;

	req.time = time;
	make_request(REQ_SETTIME, &req, sizeof (req), NULL, 0);

	local_time_valid = 0;
}

static void fill_refclock_sample(void) {
	struct Reply_getrefsample r;
	double clock_time, receive_time, round_corr;
	int i;

	if (shm_refclocks == 0 && pps_fds == 0)
		return;

	make_request(REQ_GETREFSAMPLE, NULL, 0, &r, sizeof (r));

	if (r.time == shm_refclock_time || !r.valid)
		return;
	shm_refclock_time = r.time;

	for (i = 0; i < shm_refclocks; i++) {
		if (shm_refclocks == 1) {
			clock_time = r.time - r.offset;
			receive_time = r.time;
		} else {
			clock_time = get_refclock_time();
			receive_time = get_real_time();
		}

		round_corr = (clock_time * 1e6 - floor(clock_time * 1e6) + 0.5) / 1e6;
		clock_time -= round_corr;
		receive_time -= round_corr;

		shm_time[i].count++;
		shm_time[i].clockTimeStampSec = floor(clock_time);
		shm_time[i].clockTimeStampUSec = (clock_time - shm_time[i].clockTimeStampSec) * 1e6;
		shm_time[i].clockTimeStampNSec = (clock_time - shm_time[i].clockTimeStampSec) * 1e9;
		shm_time[i].clockTimeStampSec += system_time_offset;
		shm_time[i].receiveTimeStampSec = floor(receive_time);
		shm_time[i].receiveTimeStampUSec = (receive_time - shm_time[i].receiveTimeStampSec) * 1e6;
		shm_time[i].receiveTimeStampNSec = (receive_time - shm_time[i].receiveTimeStampSec) * 1e9;
		shm_time[i].receiveTimeStampSec += system_time_offset;
		shm_time[i].leap = 0;
		shm_time[i].valid = 1;
	}
}

static int socket_in_subnet(int socket, int subnet) {
	switch (sockets[socket].iface) {
		case IFACE_LO:
			return 0;
		case IFACE_UNIX:
			return subnet == unix_subnet;
		case IFACE_ALL:
			return subnet != unix_subnet;
		default:
			return sockets[socket].iface - IFACE_ETH0 == subnet &&
				subnet != unix_subnet;
	}
}

static int get_ip_target(int socket, const struct sockaddr *saddr, socklen_t saddrlen,
			 unsigned int *subnet, unsigned int *node, unsigned int *port) {
	const struct sockaddr_in6 *sin6;
	const struct sockaddr_in *sin;
	uint32_t addr;

	switch (saddr->sa_family) {
		case AF_INET:
			sin = (const struct sockaddr_in *)saddr;
			if (saddrlen < sizeof (*sin))
				return 0;
			addr = ntohl(sin->sin_addr.s_addr);
			*port = ntohs(sin->sin_port);

			if (addr == PTP_PRIMARY_MCAST_ADDR || addr == PTP_PDELAY_MCAST_ADDR) {
				assert(sockets[socket].iface >= IFACE_ETH0);
				*subnet = sockets[socket].iface - IFACE_ETH0;
				*node = -1; /* multicast as broadcast */
				return 1;
			}
			break;
		case AF_INET6:
			sin6 = (const struct sockaddr_in6 *)saddr;
			if (saddrlen < sizeof (*sin6))
				return 0;
			*port = ntohs(sin6->sin6_port);
			if (memcmp(sin6->sin6_addr.s6_addr, PTP_PRIMARY_MCAST_ADDR6, 16) == 0 ||
			    memcmp(sin6->sin6_addr.s6_addr, PTP_PDELAY_MCAST_ADDR6, 16) == 0) {
				assert(sockets[socket].iface >= IFACE_ETH0);
				*subnet = sockets[socket].iface - IFACE_ETH0;
				*node = -1;
				return 1;
			}
			if (!IS_SIN6_KNOWN(sin6))
				return 0;
			addr = ADDR_FROM_SIN6(sin6);
			break;
		default:
			return 0;
	}

	*subnet = SUBNET_FROM_ADDR(addr);
	if (fuzz_mode && (*subnet >= subnets || *subnet == unix_subnet))
		*subnet = 0;

	assert(*subnet >= 0 && *subnet < subnets);
	assert(socket_in_subnet(socket, *subnet));

	if (addr == BROADCAST_ADDR(*subnet))
		*node = -1; /* broadcast */
	else
		*node = NODE_FROM_ADDR(addr);

	return 1;
}

static int set_sockaddr(int domain, unsigned int subnet, unsigned int node, unsigned int port,
			struct sockaddr *saddr, socklen_t *saddrlen) {
	struct sockaddr_in6 *sin6;
	struct sockaddr_in *sin;
	struct sockaddr_un *sun;

	switch (domain) {
		case AF_INET:
			assert(*saddrlen >= sizeof (*sin));
			sin = (struct sockaddr_in *)saddr;
			memset(sin, 0, sizeof (*sin));
			sin->sin_family = AF_INET;
			sin->sin_port = htons(port);
			sin->sin_addr.s_addr = htonl(NODE_ADDR(subnet, node));
			*saddrlen = sizeof (*sin);
			break;
		case AF_INET6:
			assert(*saddrlen >= sizeof (*sin6));
			sin6 = (struct sockaddr_in6 *)saddr;
			memset(sin6, 0, sizeof (*sin6));
			sin6->sin6_family = AF_INET6;
			sin6->sin6_port = htons(port);
			memcpy(sin6->sin6_addr.s6_addr, IP6_NET, 14);
			sin6->sin6_addr.s6_addr[14] = subnet;
			sin6->sin6_addr.s6_addr[15] = node + 1;
			*saddrlen = sizeof (*sin6);
			break;
		case AF_UNIX:
			assert(*saddrlen >= sizeof (*sun));
			sun = (struct sockaddr_un *)saddr;
			memset(sun, 0, sizeof (*sun));
			sun->sun_family = AF_UNIX;
			snprintf(sun->sun_path, sizeof (sun->sun_path),
				 "/clknetsim/unix/%d:%d", node + 1, port);
			*saddrlen = sizeof (*sun);
			break;
		default:
			return 0;
	}

	return 1;
}

static int get_network_from_iface(const char *iface) {
	if (strncmp(iface, "eth", 3))
		return -1;
	return atoi(iface + 3);
}

static int get_free_socket(void) {
	int i;

	for (i = 0; i < MAX_SOCKETS; i++) {
		if (!sockets[i].used)
			return i;
	}

	return -1;
}

static int get_socket_from_fd(int fd) {
	int s = fd - BASE_SOCKET_FD;

	if (s >= 0 && s < MAX_SOCKETS && sockets[s].used)
		return s;
	return -1;
}

static int get_socket_fd(int s) {
	return s + BASE_SOCKET_FD;
}

static int find_recv_socket(struct Reply_select *rep) {
	int i, s = -1;

	for (i = 0; i < MAX_SOCKETS; i++) {
		if (!sockets[i].used)
			continue;

		if (rep == NULL)
			return i;

		if (!socket_in_subnet(i, rep->subnet) ||
		    (rep->dst_port && sockets[i].port != rep->dst_port) ||
		    (sockets[i].remote_node >= 0 && sockets[i].remote_node != rep->from) ||
		    (sockets[i].remote_port >= 0 && sockets[i].remote_port != rep->src_port))
			continue;

		switch (rep->type) {
			case MSG_TYPE_NO_MSG:
				break;
			case MSG_TYPE_UDP_DATA:
				if (sockets[i].type != SOCK_DGRAM)
					continue;
				break;
			case MSG_TYPE_TCP_CONNECT:
				if (sockets[i].type != SOCK_STREAM || sockets[i].connected)
					continue;
				break;
			case MSG_TYPE_TCP_DATA:
			case MSG_TYPE_TCP_DISCONNECT:
				if (sockets[i].type != SOCK_STREAM ||
				    sockets[i].listening || !sockets[i].connected)
					continue;
				break;
			default:
				assert(0);
		}

		if (s < 0 || sockets[s].iface < sockets[i].iface ||
		    (rep->ret == REPLY_SELECT_BROADCAST && sockets[i].broadcast) ||
		    (rep->ret != REPLY_SELECT_BROADCAST && sockets[s].broadcast &&
		     !sockets[i].broadcast))
			s = i;
	}

	return s;
}

static void send_msg_to_peer(int s, int type) {
	struct Request_send req;

	assert(sockets[s].domain == AF_INET || sockets[s].domain == AF_INET6);
	assert(sockets[s].type == SOCK_STREAM);

	if (sockets[s].remote_node == -1)
		return;

	req.type = type;
	req.subnet = sockets[s].iface - IFACE_ETH0;
	req.to = sockets[s].remote_node;
	req.src_port = sockets[s].port;
	req.dst_port = sockets[s].remote_port;
	req.len = 0;

	make_request(REQ_SEND, &req, offsetof(struct Request_send, data), NULL, 0);
}

static int get_free_timer(void) {
	int i;

	for (i = 0; i < MAX_TIMERS; i++) {
		if (!timers[i].used)
			return i;
	}

	return -1;
}

static timer_t get_timerid(int timer) {
	return (timer_t)((long)timer + BASE_TIMER_ID);
}

static int get_timer_from_id(timer_t timerid) {
	int t = (long)timerid - BASE_TIMER_ID;

	if (t >= 0 && t < MAX_TIMERS && timers[t].used)
		return t;
	return -1;
}

static int get_timerfd(int timer) {
	return timer + BASE_TIMER_FD;
}

static int get_timer_from_fd(int fd) {
	int t = fd - BASE_TIMER_FD;

	if (t >= 0 && t < MAX_TIMERS && timers[t].used)
		return t;
	return -1;
}

static int get_first_timer(fd_set *timerfds) {
	int i, r = -1;

	for (i = 0; i < MAX_TIMERS; i++) {
		if (!timers[i].used || !timers[i].armed)
			continue;
		if (timers[i].type == TIMER_TYPE_FD &&
				!(timerfds && FD_ISSET(get_timerfd(i), timerfds)))
			continue;
		if (r < 0 || timers[r].timeout > timers[i].timeout)
			r = i;
	}

	return r;
}

static void rearm_timer(int timer)
{
	assert(timers[timer].armed);
	if (timers[timer].interval > 0.0)
		timers[timer].timeout += timers[timer].interval;
	else
		timers[timer].armed = 0;
	timers[timer].expired++;
}

static void time_to_timeval(double d, struct timeval *tv) {
	tv->tv_sec = floor(d);
	tv->tv_usec = (d - tv->tv_sec) * 1e6;
}

static void time_to_timespec(double d, struct timespec *tp) {
	tp->tv_sec = floor(d);
	tp->tv_nsec = (d - tp->tv_sec) * 1e9;
}

static double timeval_to_time(const struct timeval *tv, time_t offset) {
	return tv->tv_sec + offset + tv->tv_usec / 1e6;
}

static double timespec_to_time(const struct timespec *tp, time_t offset) {
	return tp->tv_sec + offset + tp->tv_nsec / 1e9;
}

static void normalize_timespec(struct timespec *tp) {
	while (tp->tv_nsec >= 1000000000) {
		tp->tv_nsec -= 1000000000;
		tp->tv_sec++;
	}
	while (tp->tv_nsec < 0) {
		tp->tv_nsec += 1000000000;
		tp->tv_sec--;
	}
}

static void add_to_timespec(struct timespec *tp, double offset) {
	tp->tv_sec += floor(offset);
	tp->tv_nsec += round((offset - floor(offset)) * 1e9);
	normalize_timespec(tp);
}

static double get_random_double(void) {
	return (double)random() / ((1U << 31) - 1);
}

static double get_phc_delay(int dir) {
	static unsigned int count = 0;
	double L, p, delay = 0.0;
	int k, lambda = 5;

	/* Poisson with uniform steps */
	if (phc_jitter > 0.0 && count >= phc_jitter_off) {
		for (L = exp(-lambda), p = 1.0, k = 0; k < 100 && p > L; k++)
			p *= get_random_double();
		delay += (k + get_random_double()) / (lambda + 0.5) *
			phc_jitter * (0.5 + dir * phc_jitter_asym);
	}

	count++;
	if (count >= phc_jitter_on + phc_jitter_off)
		count = 0;

	return (delay + phc_delay / 2.0) * (freq_error + 1.0);
}

static int generate_eth_frame(unsigned int type, unsigned int subnet, unsigned int from,
			      unsigned int to, unsigned int src_port, unsigned int dst_port,
			      char *data, unsigned int data_len, char *frame, unsigned int buf_len) {
	uint16_t port1, port2, ip_len, udp_len, len_offset, proto_offset, ip_header_len;
	uint32_t addr1, addr2;

	ip_header_len = ip_family == 6 ? 40 : 20;

	assert(type == SOCK_DGRAM || type == SOCK_STREAM);

	if ((type == SOCK_DGRAM && data_len + 14 + ip_header_len + 8 > buf_len) ||
	    (type == SOCK_STREAM && data_len + 14 + ip_header_len + 20 > buf_len))
		return 0;

	memset(frame, 0, buf_len);
	if (ip_family == 6) {
		frame[12] = 0x86;
		frame[13] = 0xDD;
		frame[14] = 0x60;
		len_offset = 14 + 4;
		ip_len = 0;
		proto_offset = 14 + 6;
		memcpy(frame + 14 + 8, IP6_NET, 16);
		frame[14 + 8 + 14] = subnet;
		frame[14 + 8 + 15] = from + 1;
		memcpy(frame + 14 + 24, IP6_NET, 16);
		frame[14 + 24 + 14] = subnet;
		frame[14 + 24 + 15] = to + 1;
	} else {
		frame[12] = 0x08;
		frame[14] = 0x45;
		len_offset = 14 + 2;
		ip_len = ip_header_len;
		proto_offset = 14 + 9;
		addr1 = htonl(NODE_ADDR(subnet, from));
		addr2 = htonl(NODE_ADDR(subnet, to));
		memcpy(frame + 14 + 12, &addr1, sizeof (addr1));
		memcpy(frame + 14 + 16, &addr2, sizeof (addr2));
	}

	port1 = htons(src_port);
	port2 = htons(dst_port);
	memcpy(frame + 14 + ip_header_len + 0, &port1, sizeof (port1));
	memcpy(frame + 14 + ip_header_len + 2, &port2, sizeof (port2));

	if (type == SOCK_DGRAM) {
		ip_len = htons(ip_len + 8 + data_len);
		udp_len = htons(data_len + 8);
		memcpy(frame + len_offset, &ip_len, sizeof (ip_len));
		frame[proto_offset] = 17;
		memcpy(frame + 14 + ip_header_len + 4, &udp_len, sizeof (udp_len));
		memcpy(frame + 14 + ip_header_len + 8, data, data_len);
		return 14 + ip_header_len + 8 + data_len;
	} else {
		ip_len = htons(ip_len + 8 + data_len);
		memcpy(frame + len_offset, &ip_len, sizeof (ip_len));
		frame[proto_offset] = 6;
		frame[14 + ip_header_len + 12] = 5 << 4;
		memcpy(frame + 14 + ip_header_len + 20, data, data_len);
		return 14 + ip_header_len + 20 + data_len;
	}
}

static void write_pcap_header(void) {
	/* Big-endian nanosecond pcap with DLT_EN10MB */
	const char header[] = "\xa1\xb2\x3c\x4d\x00\x02\x00\x04\x00\x00\x00\x00"
			      "\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x01";
	if (!pcap)
		return;
	if (fwrite(header, sizeof (header) - 1, 1, pcap) != 1)
		return;
}

static void write_pcap_packet(unsigned int type, unsigned int subnet, unsigned int from, unsigned int to,
			      unsigned int src_port, unsigned int dst_port, char *data, unsigned int len) {
	char frame[64 + MAX_PACKET_SIZE];
	unsigned int frame_len;
	struct timespec ts;
	uint32_t v;

	if (!pcap)
		return;

	clock_gettime(CLOCK_REALTIME, &ts);
	frame_len = generate_eth_frame(type, subnet, from, to, src_port, dst_port,
				       data, len, frame, sizeof (frame));

	v = htonl(ts.tv_sec);
	if (fwrite(&v, sizeof (v), 1, pcap) != 1)
		return;
	v = htonl(ts.tv_nsec);
	if (fwrite(&v, sizeof (v), 1, pcap) != 1)
		return;
	v = htonl(frame_len);
	if (fwrite(&v, sizeof (v), 1, pcap) != 1 || fwrite(&v, sizeof (v), 1, pcap) != 1)
		return;
	if (fwrite(frame, frame_len, 1, pcap) != 1)
		return;

}

int gettimeofday(struct timeval *tv,
#if !defined(__GLIBC_PREREQ) || __GLIBC_PREREQ(2, 31) || defined(GETTIMEOFDAY_VOID)
		 void *tz
#else
		 struct timezone *tz
#endif
		 ) {
	double time;

	time = get_real_time() + 0.5e-6;

	time_to_timeval(time, tv);
	tv->tv_sec += system_time_offset;

	/* old chrony clock precision routine hack */
	if (precision_hack)
		tv->tv_usec += random() % 2;

	return 0;
}

int clock_gettime(clockid_t which_clock, struct timespec *tp) {
	double time;

	/* try to allow reading of the clock from other constructors, but
	   prevent a recursive call (e.g. due to a special memory allocator) */
	init();
	if (!initialized) {
		errno = EINVAL;
		return -1;
	}

	switch (which_clock) {
		case CLOCK_REALTIME:
		case CLOCK_REALTIME_COARSE:
		case SYSCLK_CLOCKID:
			time = get_real_time();
			break;
		case CLOCK_MONOTONIC:
		case CLOCK_MONOTONIC_COARSE:
			time = get_monotonic_time();
			break;
		case REFCLK_ID:
			time = get_refclock_time();
			break;
		default:
			assert(0);
	}

	time += 0.5e-9;
	time_to_timespec(time, tp);
	
	if (which_clock != CLOCK_MONOTONIC && which_clock != CLOCK_MONOTONIC_COARSE)
		tp->tv_sec += system_time_offset;

	/* chrony and ntpd clock precision routine hack */
	if (precision_hack) {
		static int x = 0;
		tp->tv_nsec += x++ * 101;
	}

	return 0;
}

time_t time(time_t *t) {
	time_t time;

	time = floor(get_real_time());
	time += system_time_offset;
	if (t)
		*t = time;
	return time;
}

int settimeofday(const struct timeval *tv, const struct timezone *tz) {
	struct timespec ts;

	assert(tv);
	ts.tv_sec = tv->tv_sec;
	ts.tv_nsec = 1000 * tv->tv_usec;
	return clock_settime(CLOCK_REALTIME, &ts);
}

int clock_settime(clockid_t which_clock, const struct timespec *tp) {
	assert(which_clock == CLOCK_REALTIME);

	if (tp->tv_sec < 0 || tp->tv_sec > ((1LLU << 63) / 1000000000)) {
		errno = EINVAL;
		return -1;
	}

	settime(timespec_to_time(tp, -system_time_offset));
	return 0;
}

int adjtimex(struct timex *buf) {
	struct Request_adjtimex req;
	struct Reply_adjtimex rep;

	if (buf->modes & ADJ_SETOFFSET)
		local_time_valid = 0;

	memset(&req, 0, sizeof (req));
	req.timex.modes = buf->modes;
	if (buf->modes & ADJ_FREQUENCY)
		req.timex.freq = buf->freq;
	if (buf->modes & ADJ_MAXERROR)
		req.timex.maxerror = buf->maxerror;
	if (buf->modes & ADJ_ESTERROR)
		req.timex.esterror = buf->esterror;
	if (buf->modes & ADJ_STATUS)
		req.timex.status = buf->status;
	if ((buf->modes & ADJ_TIMECONST) || (buf->modes & ADJ_TAI))
		req.timex.constant = buf->constant;
	if (buf->modes & ADJ_TICK)
		req.timex.tick = buf->tick;
	if (buf->modes & ADJ_OFFSET)
		req.timex.offset = buf->offset;
	if (buf->modes & ADJ_SETOFFSET)
		req.timex.time = buf->time;

	make_request(REQ_ADJTIMEX, &req, sizeof (req), &rep, sizeof (rep));
	*buf = rep.timex;
	
	if (rep.ret < 0)
		errno = EINVAL;

	return rep.ret;
}

int ntp_adjtime(struct timex *buf) {
	return adjtimex(buf);
}

int clock_adjtime(clockid_t id, struct timex *tx) {
	assert(id == CLOCK_REALTIME || id == SYSCLK_CLOCKID || id == REFCLK_ID);

	if (id == SYSCLK_CLOCKID) {
		/* allow large frequency adjustment by setting ticks */

		long hz, base_tick, scaled_ppm_per_tick;
		int r;

		hz = sysconf(_SC_CLK_TCK);
		assert(hz > 0);
		base_tick = (1000000 + hz / 2) / hz;
		scaled_ppm_per_tick = 65536 * hz;

		if (tx->modes & ADJ_FREQUENCY && !(tx->modes & ADJ_TICK))
			tx->tick = base_tick, tx->modes |= ADJ_TICK;

		tx->tick += tx->freq / scaled_ppm_per_tick;
		tx->freq = tx->freq % scaled_ppm_per_tick;

		r = adjtimex(tx);

		tx->freq += (tx->tick - base_tick) * scaled_ppm_per_tick;
		tx->tick = base_tick;

		return r;
	} else if (id == REFCLK_ID) {
		if (tx->modes) {
			errno = EINVAL;
			return -1;
		}

		memset(tx, 0, sizeof (*tx));
		return 0;
	}

	return adjtimex(tx);
}

int adjtime(const struct timeval *delta, struct timeval *olddelta) {
	struct Request_adjtime req;
	struct Reply_adjtime rep;

	if (delta)
		req.tv = *delta;
	else
		time_to_timeval(0.0, &req.tv);

	make_request(REQ_ADJTIME, &req, sizeof (req), &rep, sizeof (rep));
	if (olddelta)
		*olddelta = rep.tv;

	if (!delta) {
		req.tv = rep.tv;
		make_request(REQ_ADJTIME, &req, sizeof (req), &rep, sizeof (rep));
	}
	
	return 0;
}

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
	struct Request_select req;
	struct Reply_select rep;
	int i, timer, s, recv_fd = -1;
	double elapsed = 0.0;

	req.read = 0;
	req._pad = 0;

	if (writefds) {
		for (i = 0; i < nfds; i++) {
			if (!FD_ISSET(i, writefds))
				continue;
			s = get_socket_from_fd(i);
			if (s < 0)
				continue;
			if (sockets[s].type == SOCK_STREAM && !sockets[s].connected) {
				req.read = 1;
				continue;
			}
			FD_ZERO(writefds);
			FD_SET(i, writefds);
			if (exceptfds)
				FD_ZERO(exceptfds);
			if (readfds)
				FD_ZERO(readfds);
			return 1;
		}

		FD_ZERO(writefds);
	}

	if (exceptfds) {
		/* TX timestamp available in the error queue */
		for (i = 0; i < nfds; i++) {
			if (!FD_ISSET(i, exceptfds) || get_socket_from_fd(i) < 0 ||
					!sockets[get_socket_from_fd(i)].last_ts_msg.len)
				continue;
			if (readfds)
				FD_ZERO(readfds);
			FD_ZERO(exceptfds);
			FD_SET(i, exceptfds);
			return 1;
		}

		FD_ZERO(exceptfds);
	}

	/* unknown reading fds are always ready (e.g. chronyd waiting
	   for name resolving notification, or OpenSSL waiting for
	   /dev/urandom) */
	if (readfds) {
		for (i = 0; i < nfds; i++) {
			if (!FD_ISSET(i, readfds))
				continue;

			if (i == RTC_FD) {
				if (rtc_timerfd > 0)
					FD_SET(rtc_timerfd, readfds);
				continue;
			}

			s = get_socket_from_fd(i);
			if ((s < 0 && get_timer_from_fd(i) < 0) ||
			    (s >= 0 && sockets[s].buffer.len > 0)) {
				FD_ZERO(readfds);
				FD_SET(i, readfds);
				return 1;
			}
			req.read = 1;
		}
	}

	timer = get_first_timer(readfds);

	assert(timeout || timer >= 0 || find_recv_socket(NULL) >= 0);

	fetch_time();

	if (timeout)
		req.timeout = timeout->tv_sec + (timeout->tv_usec + 1) / 1e6;
	else
		req.timeout = 1e20;

try_again:
	if (timer >= 0 && timers[timer].timeout <= monotonic_time) {
		/* avoid unnecessary requests */
		rep.ret = REPLY_SELECT_TIMEOUT;
	} else {
		if (timer >= 0 && monotonic_time + req.timeout > timers[timer].timeout)
			req.timeout = timers[timer].timeout - monotonic_time;

		make_request(REQ_SELECT, &req, sizeof (req), &rep, sizeof (rep));

		elapsed += rep.time.monotonic_time - monotonic_time;
		req.timeout -= rep.time.monotonic_time - monotonic_time;

		real_time = rep.time.real_time;
		monotonic_time = rep.time.monotonic_time;
		network_time = rep.time.network_time;
		freq_error = rep.time.freq_error;
		local_time_valid = 1;

		fill_refclock_sample();

		if (monotonic_time >= 0.1 || timer >= 0 || rep.ret != REPLY_SELECT_TIMEOUT)
			precision_hack = 0;
	}

	switch (rep.ret) {
		case REPLY_SELECT_TERMINATE:
			kill(getpid(), SIGTERM);
			errno = EINTR;
			return -1;

		case REPLY_SELECT_TIMEOUT:
			if (timer >= 0 && monotonic_time >= timers[timer].timeout) {
				rearm_timer(timer);
				switch (timers[timer].type) {
					case TIMER_TYPE_SIGNAL:
						kill(getpid(), SIGALRM);
						errno = EINTR;
						return -1;
					case TIMER_TYPE_FD:
						recv_fd = get_timerfd(timer);
						break;
					default:
						assert(0);
				}
			} else
				recv_fd = 0;
			break;

		case REPLY_SELECT_NORMAL:
		case REPLY_SELECT_BROADCAST:
			s = find_recv_socket(&rep);

			if (s >= 0 && rep.type == MSG_TYPE_TCP_CONNECT &&
			    !sockets[s].listening && !sockets[s].connected) {
				struct Reply_recv recv_rep;

				/* drop the connection packet and let the client repeat the call
				   in order to see that the socket is ready for writing */
				make_request(REQ_RECV, NULL, 0, &recv_rep, sizeof (recv_rep));

				assert(recv_rep.type == MSG_TYPE_TCP_CONNECT);
				assert(sockets[s].type == SOCK_STREAM);
				sockets[s].connected = 1;
				errno = EINTR;
				return -1;
			}

			recv_fd = s >= 0 ? get_socket_fd(s) : 0;

			/* fetch and drop the packet if no fd is waiting for it */
			if (!readfds || !recv_fd || !FD_ISSET(recv_fd, readfds)) {
				struct Reply_recv recv_rep;

				make_request(REQ_RECV, NULL, 0, &recv_rep, sizeof (recv_rep));
				if (rep.ret != REPLY_SELECT_BROADCAST) {
					if (s >= 0 && sockets[s].buffer.len == 0) {
						sockets[s].buffer.len = recv_rep.len;
						assert(sockets[s].buffer.len <= sizeof (sockets[s].buffer.data));
						memcpy(sockets[s].buffer.data, recv_rep.data, sockets[s].buffer.len);
						sockets[s].buffer.subnet = recv_rep.subnet;
						sockets[s].buffer.to_from = recv_rep.from;
						sockets[s].buffer.port = recv_rep.src_port;
					} else {
						fprintf(stderr, "clknetsim: dropped packet of type %d from "
								"node %d on port %d in subnet %d\n",
								recv_rep.type, recv_rep.from + 1,
								recv_rep.dst_port, recv_rep.subnet + 1);
					}
				}

				goto try_again;
			}
			break;
		default:
			assert(0);
			return 0;
	}

	assert(!recv_fd || (readfds && FD_ISSET(recv_fd, readfds)));
	assert(!recv_fd || (recv_fd >= BASE_SOCKET_FD && recv_fd < BASE_SOCKET_FD + MAX_SOCKETS) ||
			(recv_fd >= BASE_TIMER_FD && recv_fd < BASE_TIMER_FD + MAX_TIMERS));

	if (readfds) {
		FD_ZERO(readfds);
		if (recv_fd) {
			if (recv_fd == rtc_timerfd)
				recv_fd = RTC_FD;
			FD_SET(recv_fd, readfds);
		}
	}

	if (timeout) {
		time_to_timeval(timeval_to_time(timeout, 0) - elapsed, timeout);
		if (timeout->tv_sec < 0) {
			timeout->tv_sec = 0;
			timeout->tv_usec = 0;
		}
	}

	return recv_fd ? 1 : 0;
}

#ifndef CLKNETSIM_DISABLE_POLL
int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
	struct timeval tv, *ptv = NULL;
	fd_set rfds, wfds, efds;
	int r, maxfd = 0;
	nfds_t i;

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&efds);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
	for (i = 0; i < nfds; i++) {
		if (fds[i].fd < 0)
		       continue;
		assert(fds[i].fd < FD_SETSIZE);
		if (fds[i].events & POLLIN)
			FD_SET(fds[i].fd, &rfds);
		if (fds[i].events & POLLOUT)
			FD_SET(fds[i].fd, &wfds);
		if (fds[i].events & POLLPRI)
			FD_SET(fds[i].fd, &efds);
		if (maxfd < fds[i].fd)
			maxfd = fds[i].fd;
	}
#pragma GCC diagnostic pop

	if (timeout >= 0) {
		tv.tv_sec = timeout / 1000;
		tv.tv_usec = (timeout % 1000) * 1000;
		ptv = &tv;
	}

	r = select(maxfd + 1, &rfds, &wfds, &efds, ptv);
	if (r < 0)
		return r;

	for (i = 0, r = 0; i < nfds; i++) {
		fds[i].revents = 0;
		if (fds[i].fd < 0)
			continue;
		if (FD_ISSET(fds[i].fd, &rfds))
			fds[i].revents |= POLLIN;
		if (FD_ISSET(fds[i].fd, &wfds))
			fds[i].revents |= POLLOUT;
		if (FD_ISSET(fds[i].fd, &efds))
			fds[i].revents |= POLLPRI;
		if (fds[i].revents)
			r++;
	}

	return r;
}

int __poll_chk(struct pollfd *fds, nfds_t nfds, int timeout, size_t fdslen) {
	return poll(fds, nfds, timeout);
}

#endif

int usleep(useconds_t usec) {
	struct timeval tv;
	int r;

	tv.tv_sec = usec / 1000000;
	tv.tv_usec = usec % 1000000;

	r = select(0, NULL, NULL, NULL, &tv);
	assert(r <= 0);

	return 0;
}

int nanosleep(const struct timespec *req, struct timespec *rem) {
	struct timeval tv;
	int r;

	tv.tv_sec = req->tv_sec;
	tv.tv_usec = req->tv_nsec / 1000 + 1;

	r = select(0, NULL, NULL, NULL, &tv);
	assert(r <= 0);

	if (r < 0) {
		assert(!rem);
		return r;
	}

	if (rem)
		rem->tv_sec = rem->tv_nsec = 0;

	return 0;
}

int clock_nanosleep(clockid_t clock_id, int flags,
		const struct timespec *request,
		struct timespec *remain) {
	assert(clock_id == CLOCK_MONOTONIC || clock_id == CLOCK_REALTIME);
	return nanosleep(request, remain);
}

int eventfd(unsigned int initval, int flags) {
	/* dummy file descriptor to disable libevent thread notification */
	return timerfd_create(CLOCK_REALTIME, 0);
}

FILE *fopen(const char *path, const char *mode) {
	if (!strcmp(path, "/proc/net/if_inet6")) {
		errno = ENOENT;
		return NULL;
	} else if (!strcmp(path, "/dev/urandom")) {
		return URANDOM_FILE;
	}

	/* make sure _fopen is initialized in case it is called from another
	   constructor (e.g. OpenSSL's libcrypto) */
	init_symbols();

	return _fopen(path, mode);
}

FILE *fopen64(const char *path, const char *mode) {
	return fopen(path, mode);
}

FILE *fdopen(int fd, const char *mode) {
	if (fd == URANDOM_FD)
		return URANDOM_FILE;

	init_symbols();

	return _fdopen(fd, mode);
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
	if (stream == URANDOM_FILE) {
		if (read(URANDOM_FD, ptr, size * nmemb) != size * nmemb)
		    assert(0);

		return nmemb;
	}

	return _fread(ptr, size, nmemb, stream);
}

size_t __fread_chk(void *ptr, size_t ptrlen, size_t size, size_t nmemb, FILE *stream) {
	return fread(ptr, size, nmemb, stream);
}

int fileno(FILE *stream) {
	if (stream == URANDOM_FILE)
		return -1;

	return _fileno(stream);
}

int fclose(FILE *fp) {
	if (fp == URANDOM_FILE)
		return 0;
	return _fclose(fp);
}

char *realpath(const char *path, char *resolved_path) {
	if (!strncmp(path, "/dev/ptp", 8)) {
		snprintf(resolved_path, PATH_MAX, "%s", path);
		return resolved_path;
	}

	return _realpath(path, resolved_path);
}

char *__realpath_chk(const char *name, char *resolved_path, size_t buflen) {
	return realpath(name, resolved_path);
}

int mkdir(const char *pathname, mode_t mode) {
	if (!strncmp(pathname, "/clknetsim/unix/", 16))
		return 0;

	return _mkdir(pathname, mode);
}

int mkdirat(int dirfd, const char *pathname, mode_t mode) {
	if (dirfd == UNIX_DIR_FD)
		return 0;

	return _mkdirat(dirfd, pathname, mode);
}

int open(const char *pathname, int flags, ...) {
	int r, mode_arg = 0;
	mode_t mode = 0;
	va_list ap;

	mode_arg = flags & O_CREAT || (flags & O_TMPFILE) == O_TMPFILE;

	if (mode_arg) {
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}

	assert(REFCLK_PHC_INDEX == 0 && SYSCLK_PHC_INDEX == 1);
	if (!strcmp(pathname, "/dev/ptp0"))
		return phc_swap ? SYSCLK_FD : REFCLK_FD;
	else if (!strcmp(pathname, "/dev/ptp1"))
		return phc_swap ? REFCLK_FD : SYSCLK_FD;
	else if (!strcmp(pathname, "/dev/pps0"))
		return pps_fds++, PPS_FD;
	else if (!strcmp(pathname, "/dev/rtc"))
		return RTC_FD;
	else if (!strcmp(pathname, "/dev/urandom"))
		return URANDOM_FD;
	else if (!strncmp(pathname, "/clknetsim/unix/", 16))
		return UNIX_DIR_FD;

	init_symbols();

	if (mode_arg)
		r = _open(pathname, flags, mode);
	else
		r = _open(pathname, flags);

	assert(r < 0 || (r < BASE_SOCKET_FD && r < BASE_TIMER_FD));

	return r;
}

int __open_2(const char *pathname, int oflag) {
	return open(pathname, oflag);
}

ssize_t read(int fd, void *buf, size_t count) {
	int t;

	if (fd == URANDOM_FD) {
		size_t i;
		long r;

		assert(RAND_MAX >= 0xffffff);
		for (i = r = 0; i < count; i++) {
			if (i % 3)
				r >>= 8;
			else
				r = random();
			((unsigned char *)buf)[i] = r;
		}

		return count;
	} else if (fd == RTC_FD) {
		unsigned long d = RTC_UF | 1 << 8;
		if (count < sizeof (d)) {
			errno = EINVAL;
			return -1;
		}
		memcpy(buf, &d, sizeof (d));
		return sizeof (d);
	} else if ((t = get_timer_from_fd(fd)) >= 0) {
		if (count < sizeof (timers[t].expired)) {
			errno = EINVAL;
			return -1;
		}

		assert(timers[t].expired > 0);
		memcpy(buf, &timers[t].expired, sizeof (timers[t].expired));
		timers[t].expired = 0;
		return sizeof (timers[t].expired);
	}

	return _read(fd, buf, count);
}

ssize_t __read_chk(int fd, void *buf, size_t count, size_t buflen) {
	return read(fd, buf, count);
}

int close(int fd) {
	int t, s;

	if (fd == REFCLK_FD || fd == SYSCLK_FD || fd == RTC_FD || fd == URANDOM_FD ||
	    fd == UNIX_DIR_FD) {
		return 0;
	} else if (fd == PPS_FD) {
		pps_fds--;
		return 0;
	} else if ((t = get_timer_from_fd(fd)) >= 0) {
		return timer_delete_(get_timerid(t));
	} else if ((s = get_socket_from_fd(fd)) >= 0) {
		if (sockets[s].type == SOCK_STREAM)
			shutdown(fd, SHUT_RDWR);
		sockets[s].used = 0;
		return 0;
	}

	return _close(fd);
}

int socket(int domain, int type, int protocol) {
	int s;

	if (((domain != AF_INET || ip_family == 6) &&
	     (domain != AF_INET6 || ip_family == 4) &&
	     (domain != AF_UNIX || unix_subnet < 0)) ||
	    (type != SOCK_DGRAM && type != SOCK_STREAM)) {
		errno = EINVAL;
		return -1;
	}

	s = get_free_socket();
	if (s < 0) {
		errno = ENOMEM;
		return -1;
	}

	memset(sockets + s, 0, sizeof (struct socket));
	sockets[s].used = 1;
	sockets[s].domain = domain;
	sockets[s].type = type;
	sockets[s].port = BASE_SOCKET_DEFAULT_PORT + s;
	sockets[s].iface = domain == AF_UNIX ? IFACE_UNIX : IFACE_ALL;
	sockets[s].remote_node = -1;
	sockets[s].remote_port = -1;

	return get_socket_fd(s);
}

int listen(int sockfd, int backlog) {
	int s = get_socket_from_fd(sockfd);

	if (s < 0 || (sockets[s].domain != AF_INET && sockets[s].domain != AF_INET6) ||
	    sockets[s].type != SOCK_STREAM) {
		errno = EINVAL;
		return -1;
	}

	sockets[s].listening = 1;

	return 0;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	int s = get_socket_from_fd(sockfd), r;
	struct Reply_recv rep;

	if (s < 0 || (sockets[s].domain != AF_INET && sockets[s].domain != AF_INET6) ||
	    sockets[s].type != SOCK_STREAM) {
		errno = EINVAL;
		return -1;
	}

	make_request(REQ_RECV, NULL, 0, &rep, sizeof (rep));
	assert(rep.type == MSG_TYPE_TCP_CONNECT);

	r = socket(sockets[s].domain, SOCK_STREAM, 0);
	s = get_socket_from_fd(r);
	assert(s >= 0);

	sockets[s].port = rep.dst_port;
	sockets[s].iface = IFACE_ETH0 + rep.subnet;
	sockets[s].remote_node = rep.from;
	sockets[s].remote_port = rep.src_port;
	sockets[s].connected = 1;

	set_sockaddr(sockets[s].domain, sockets[s].iface - IFACE_ETH0, node,
		     sockets[s].remote_port, addr, addrlen);

	send_msg_to_peer(s, MSG_TYPE_TCP_CONNECT);

	return r;
}

int shutdown(int sockfd, int how) {
	int s = get_socket_from_fd(sockfd);

	if (s < 0) {
		assert(0);
		errno = EINVAL;
		return -1;
	}

	assert(sockets[s].domain == AF_INET || sockets[s].domain == AF_INET6);
	assert(sockets[s].type == SOCK_STREAM);

	if (sockets[s].connected) {
		send_msg_to_peer(s, MSG_TYPE_TCP_DISCONNECT);
		sockets[s].connected = 0;
	}

	return 0;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	/* ntpd uses connect() and getsockname() to find the interface
	   which will be used to send packets to an address */
	int s = get_socket_from_fd(sockfd);
	unsigned int node, subnet, port;
	struct sockaddr_un *sun;

	if (s < 0) {
		errno = EINVAL;
		return -1;
	}

	switch (addr->sa_family) {
		case AF_INET:
		case AF_INET6:
			if (!get_ip_target(s, addr, addrlen, &subnet, &node, &port) ||
			    node == -1) {
				errno = EINVAL;
				return -1;
			}

			sockets[s].iface = IFACE_ETH0 + subnet;
			sockets[s].remote_node = node;
			sockets[s].remote_port = port;
			break;
		case AF_UNIX:
			sun = (struct sockaddr_un *)addr;
			assert(addrlen > offsetof(struct sockaddr_un, sun_path) + 1);

			assert(sockets[s].iface == IFACE_UNIX);
			if (sscanf(sun->sun_path, "/clknetsim/unix/%d:%d",
				   &sockets[s].remote_node, &sockets[s].remote_port) != 2) {
				errno = EINVAL;
				return -1;
			}
			sockets[s].remote_node--;
			break;
		default:
			errno = EINVAL;
			return -1;
	}

	if (sockets[s].type == SOCK_STREAM)
		send_msg_to_peer(s, MSG_TYPE_TCP_CONNECT);

	return 0;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	int s = get_socket_from_fd(sockfd), port;
	struct sockaddr_in6 *sin6;
	struct sockaddr_in *sin;
	uint32_t a;
	static int unix_sockets = 0;

	if (s < 0) {
		errno = EINVAL;
		return -1;
	}

	switch (addr->sa_family) {
		case AF_INET:
			assert(addrlen >= sizeof (*sin));
			sin = (struct sockaddr_in *)addr;

			port = ntohs(sin->sin_port);
			if (port)
				sockets[s].port = port;

			a = ntohl(sin->sin_addr.s_addr);

			if (a == INADDR_ANY) {
				sockets[s].iface = IFACE_ALL;
			} else if (a == INADDR_LOOPBACK) {
				sockets[s].iface = IFACE_LO;
			} else {
				int subnet = SUBNET_FROM_ADDR(a);
				assert(subnet >= 0 && subnet < subnets);
				if (a == NODE_ADDR(subnet, node)) {
					sockets[s].iface = IFACE_ETH0 + subnet;
				} else if (a == BROADCAST_ADDR(subnet)) {
					sockets[s].iface = IFACE_ETH0 + subnet;
					sockets[s].broadcast = 1;
				} else {
					assert(0);
				}
			}
			break;
		case AF_INET6:
			assert(addrlen >= sizeof (*sin6));
			sin6 = (struct sockaddr_in6 *)addr;

			port = ntohs(sin6->sin6_port);
			if (port)
				sockets[s].port = port;

			if (memcmp(sin6->sin6_addr.s6_addr, in6addr_any.s6_addr, 16) == 0) {
				sockets[s].iface = IFACE_ALL;
			} else if (memcmp(sin6->sin6_addr.s6_addr, in6addr_loopback.s6_addr, 16) == 0) {
				sockets[s].iface = IFACE_LO;
			} else {
				int subnet = SUBNET_FROM_SIN6(sin6);
				assert(IS_SIN6_KNOWN(sin6));
				assert(subnet >= 0 && subnet < subnets);
				assert(NODE_FROM_SIN6(sin6) == node);
				sockets[s].iface = IFACE_ETH0 + subnet;
			}
			break;
		case AF_UNIX:
			assert(addrlen > offsetof(struct sockaddr_un, sun_path) + 1);

			assert(sockets[s].iface == IFACE_UNIX);
			sockets[s].port = ++unix_sockets;
			break;
		default:
			errno = EINVAL;
			return -1;
	}

	return 0;
}

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	int s = get_socket_from_fd(sockfd);
	uint32_t a;

	if (s < 0 || (sockets[s].domain != AF_INET && sockets[s].domain != AF_INET6)) {
		errno = EINVAL;
		return -1;
	}

	if (sockets[s].domain == AF_INET6) {
		return !set_sockaddr(sockets[s].domain, sockets[s].iface - IFACE_ETH0,
				     node, sockets[s].port, addr, addrlen);
	}

	struct sockaddr_in *in;
	in = (struct sockaddr_in *)addr;
	assert(*addrlen >= sizeof (*in));
	*addrlen = sizeof (*in);
	in->sin_family = AF_INET;
	in->sin_port = htons(sockets[s].port);

	switch (sockets[s].iface) {
		case IFACE_ALL:
			a = INADDR_ANY;
			break;
		case IFACE_UNIX:
			assert(0);
		case IFACE_LO:
			a = INADDR_LOOPBACK;
			break;
		default:
			assert(sockets[s].iface - IFACE_ETH0 < subnets);
			a = sockets[s].broadcast ?
				BROADCAST_ADDR(sockets[s].iface - IFACE_ETH0) :
				NODE_ADDR(sockets[s].iface - IFACE_ETH0, node);
	}

	in->sin_addr.s_addr = htonl(a);

	return 0;
}

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
	int subnet, s = get_socket_from_fd(sockfd);

	if (s < 0 || (sockets[s].domain != AF_INET && sockets[s].domain != AF_INET6)) {
		errno = EINVAL;
		return -1;
	}

	if (level == SOL_SOCKET && optname == SO_BINDTODEVICE) {
		if (!strcmp(optval, "lo"))
			sockets[s].iface = IFACE_LO;
		else if ((subnet = get_network_from_iface(optval)) >= 0)
			sockets[s].iface = IFACE_ETH0 + subnet;
		else {
			errno = EINVAL;
			return -1;
		}
	}
	else if (optlen == sizeof (int) && ((level == IPPROTO_IP && optname == IP_PKTINFO) ||
					    (level == IPPROTO_IPV6 && optname == IPV6_RECVPKTINFO)))
		sockets[s].pkt_info = !!(int *)optval;
#ifdef SO_TIMESTAMPING
	else if (level == SOL_SOCKET && optname == SO_TIMESTAMPING && optlen >= sizeof (int)) {
		if (!timestamping) {
			errno = EINVAL;
			return -1;
		}
		sockets[s].time_stamping = *(int *)optval;
	}
#endif

	/* unhandled options succeed too */
	return 0;
}

int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen) {
	int s = get_socket_from_fd(sockfd);

	if (s < 0 || (sockets[s].domain != AF_INET && sockets[s].domain != AF_INET6)) {
		errno = EINVAL;
		return -1;
	}

	if (level == SOL_SOCKET && optname == SO_ERROR && *optlen == sizeof (int)) {
		*(int *)optval = 0;
	} else {
		errno = EINVAL;
		return -1;
	}

	return 0;
}

int fcntl(int fd, int cmd, ...) {
	int i, s = get_socket_from_fd(fd);
	va_list ap;

	if (fd == RTC_FD)
		return 0;

	if (s < 0) {
		switch (cmd) {
			/* including fcntl.h breaks open() declaration */
			case 0: /* F_DUPFD */
			case 3: /* F_GETFL */
			case 4: /* F_SETFL */
				va_start(ap, cmd);
				i = va_arg(ap, int);
				va_end(ap);
				return _fcntl(fd, cmd, i);
		}
	}

	return 0;
}

int fstat(int fd, struct stat *statbuf) {
	if (fd == URANDOM_FD)
		return stat("/dev/urandom", statbuf);

	if (fd == REFCLK_FD || fd == SYSCLK_FD) {
		memset(statbuf, 0, sizeof (*statbuf));
		statbuf->st_mode = S_IFCHR | 0660;
		statbuf->st_rdev = makedev(247, fd == REFCLK_FD ? 0 : 1);
		return 0;
	}

	if (fd == UNIX_DIR_FD) {
		memset(statbuf, 0, sizeof (*statbuf));
		statbuf->st_mode = S_IFDIR | 0711;
		return 0;
	}

#ifdef HAVE_STAT
	assert(_fstat);
	return _fstat(fd, statbuf);
#else
	assert(_fxstat);
	return _fxstat(_STAT_VER, fd, statbuf);
#endif
}

int __fxstat(int ver, int fd, struct stat *stat_buf) {
	return fstat(fd, stat_buf);
}

int stat(const char *pathname, struct stat *statbuf) {
	if (strcmp(pathname, "/clknetsim") == 0 ||
	    strcmp(pathname, "/clknetsim/unix") == 0) {
		memset(statbuf, 0, sizeof (*statbuf));
		statbuf->st_mode = S_IFDIR | 0750;
		return 0;
	}

	init_symbols();

#ifdef HAVE_STAT
	assert(_stat);
	return _stat(pathname, statbuf);
#else
	assert(_xstat);
	return _xstat(_STAT_VER, pathname, statbuf);
#endif
}

int __xstat(int ver, const char *pathname, struct stat *statbuf) {
	return stat(pathname, statbuf);
}

int chmod(const char *pathname, mode_t mode) {
	return 0;
}

int fchmod(int fd, mode_t mode) {
	return 0;
}

int ioctl(int fd, unsigned long request, ...) {
	int i, j, n, subnet, ret = 0, s = get_socket_from_fd(fd);
	va_list ap;
	struct ifconf *conf;
	struct ifreq *req;

	va_start(ap, request);

	if (request == SIOCGIFCONF) {
		conf = va_arg(ap, struct ifconf *);
		n = 1 + subnets - (unix_subnet >= 0 ? 1 : 0);
		assert(conf->ifc_len >= sizeof (struct ifreq) * n);
		conf->ifc_len = sizeof (struct ifreq) * n;
		sprintf(conf->ifc_req[0].ifr_name, "lo");
		((struct sockaddr_in*)&conf->ifc_req[0].ifr_addr)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		conf->ifc_req[0].ifr_addr.sa_family = AF_INET;

		for (i = 0, j = 1; i < subnets && j < n; i++) {
			if (i == unix_subnet)
				continue;
			sprintf(conf->ifc_req[j].ifr_name, "eth%d", i);
			((struct sockaddr_in *)&conf->ifc_req[j].ifr_addr)->sin_addr.s_addr =
				htonl(NODE_ADDR(i, node));
			conf->ifc_req[j].ifr_addr.sa_family = AF_INET;
			j++;
		}
	} else if (request == SIOCGIFINDEX) {
		req = va_arg(ap, struct ifreq *);
		if (!strcmp(req->ifr_name, "lo"))
			req->ifr_ifindex = 0;
		else if ((subnet = get_network_from_iface(req->ifr_name)) >= 0)
			req->ifr_ifindex = subnet + 1;
		else
			ret = -1, errno = EINVAL;
	} else if (request == SIOCGIFFLAGS) {
		req = va_arg(ap, struct ifreq *);
		if (!strcmp(req->ifr_name, "lo"))
			req->ifr_flags = IFF_UP | IFF_LOOPBACK;
		else if (get_network_from_iface(req->ifr_name) >= 0)
			req->ifr_flags = IFF_UP | IFF_BROADCAST;
		else
			ret = -1, errno = EINVAL;
	} else if (request == SIOCGIFBRDADDR) {
		req = va_arg(ap, struct ifreq *);
		if ((subnet = get_network_from_iface(req->ifr_name)) >= 0)
			((struct sockaddr_in*)&req->ifr_broadaddr)->sin_addr.s_addr = htonl(BROADCAST_ADDR(subnet));
		else
			ret = -1, errno = EINVAL;
		req->ifr_broadaddr.sa_family = AF_INET;
	} else if (request == SIOCGIFNETMASK) {
		req = va_arg(ap, struct ifreq *);
		if (!strcmp(req->ifr_name, "lo"))
			((struct sockaddr_in*)&req->ifr_netmask)->sin_addr.s_addr = htonl(0xff000000);
		else if (get_network_from_iface(req->ifr_name) >= 0)
			((struct sockaddr_in*)&req->ifr_netmask)->sin_addr.s_addr = htonl(NETMASK);
		else
			ret = -1, errno = EINVAL;
		req->ifr_netmask.sa_family = AF_INET;
	} else if (request == SIOCGIFHWADDR) {
		req = va_arg(ap, struct ifreq *);
		if (!strcmp(req->ifr_name, "lo"))
			memset((&req->ifr_hwaddr)->sa_data, 0, IFHWADDRLEN);
		else if ((subnet = get_network_from_iface(req->ifr_name)) >= 0) {
			char mac[IFHWADDRLEN] = {0x12, 0x34, 0x56, 0x78, subnet + 1, node + 1};
			memcpy((&req->ifr_hwaddr)->sa_data, mac, sizeof (mac));
		} else
			ret = -1, errno = EINVAL;
		req->ifr_netmask.sa_family = AF_UNSPEC;
	} else if (request == SIOCETHTOOL) {
		struct ethtool_cmd *cmd;
		req = va_arg(ap, struct ifreq *);
		cmd = (struct ethtool_cmd *)req->ifr_data;

		if (cmd->cmd == ETHTOOL_GSET) {
			memset(cmd, 0, sizeof (*cmd));
			ethtool_cmd_speed_set(cmd, link_speed);
#ifdef ETHTOOL_GET_TS_INFO
		} else if (cmd->cmd == ETHTOOL_GET_TS_INFO) {
			struct ethtool_ts_info *info;
			info = (struct ethtool_ts_info *)req->ifr_data;
			memset(info, 0, sizeof (*info));
			if (get_network_from_iface(req->ifr_name) >= 0) {
				info->phc_index = timestamping > 1 ? REFCLK_PHC_INDEX : SYSCLK_PHC_INDEX;
				info->so_timestamping = SOF_TIMESTAMPING_SOFTWARE |
					SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_RX_SOFTWARE |
					SOF_TIMESTAMPING_RAW_HARDWARE |
					SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_RX_HARDWARE;
				info->tx_types = HWTSTAMP_TX_ON;
				info->rx_filters = 1 << HWTSTAMP_FILTER_NONE | 1 << HWTSTAMP_FILTER_ALL;
			} else
				ret = -1, errno = EINVAL;
#endif
		} else
			ret = -1, errno = EINVAL;
#ifdef PTP_CLOCK_GETCAPS
	} else if (request == PTP_CLOCK_GETCAPS && (fd == REFCLK_FD || fd == SYSCLK_FD)) {
		struct ptp_clock_caps *caps = va_arg(ap, struct ptp_clock_caps *);
		memset(caps, 0, sizeof (*caps));
		/* maximum frequency in 32-bit timex.freq */
		caps->max_adj = 32767999;
#endif
#ifdef PTP_SYS_OFFSET
	} else if (request == PTP_SYS_OFFSET && fd == REFCLK_FD) {
		struct ptp_sys_offset *sys_off = va_arg(ap, struct ptp_sys_offset *);
		struct timespec ts, ts1, ts2;
		double delay;
		int i;

		if (sys_off->n_samples > PTP_MAX_SAMPLES)
			sys_off->n_samples = PTP_MAX_SAMPLES;

		clock_gettime(CLOCK_REALTIME, &ts);
		sys_off->ts[sys_off->n_samples * 2].sec = ts.tv_sec;
		sys_off->ts[sys_off->n_samples * 2].nsec = ts.tv_nsec;

		for (delay = 0.0, i = sys_off->n_samples - 1; i >= 0; i--) {
			delay += get_phc_delay(1);
			clock_gettime(REFCLK_ID, &ts1);
			add_to_timespec(&ts1, -delay);
			ts2 = ts;
			delay += get_phc_delay(-1);
			add_to_timespec(&ts2, -delay);
			sys_off->ts[2 * i + 1].sec = ts1.tv_sec;
			sys_off->ts[2 * i + 1].nsec = ts1.tv_nsec;
			sys_off->ts[2 * i + 0].sec = ts2.tv_sec;
			sys_off->ts[2 * i + 0].nsec = ts2.tv_nsec;
		}
#endif
#ifdef PTP_SYS_OFFSET_EXTENDED
	} else if (request == PTP_SYS_OFFSET_EXTENDED && fd == REFCLK_FD) {
		struct ptp_sys_offset_extended *sys_off = va_arg(ap, struct ptp_sys_offset_extended *);
		struct timespec ts, ts1, ts2;
		double delay;
		int i;

		if (sys_off->n_samples > PTP_MAX_SAMPLES)
			sys_off->n_samples = PTP_MAX_SAMPLES;

		for (i = 0; i < sys_off->n_samples; i++) {
			clock_gettime(CLOCK_REALTIME, &ts2);
			clock_gettime(REFCLK_ID, &ts);
			delay = get_phc_delay(1);
			add_to_timespec(&ts, -delay);
			delay += get_phc_delay(-1);
			ts1 = ts2;
			add_to_timespec(&ts1, -delay);
			sys_off->ts[i][0].sec = ts1.tv_sec;
			sys_off->ts[i][0].nsec = ts1.tv_nsec;
			sys_off->ts[i][1].sec = ts.tv_sec;
			sys_off->ts[i][1].nsec = ts.tv_nsec;
			sys_off->ts[i][2].sec = ts2.tv_sec;
			sys_off->ts[i][2].nsec = ts2.tv_nsec;
		}
#endif
#ifdef PTP_SYS_OFFSET_PRECISE
	} else if (request == PTP_SYS_OFFSET_PRECISE && fd == REFCLK_FD) {
		struct ptp_sys_offset_precise *sys_off = va_arg(ap, struct ptp_sys_offset_precise *);
		struct timespec ts;

		clock_gettime(REFCLK_ID, &ts);
		sys_off->device.sec = ts.tv_sec;
		sys_off->device.nsec = ts.tv_nsec;

		clock_gettime(CLOCK_REALTIME, &ts);
		sys_off->sys_realtime.sec = ts.tv_sec;
		sys_off->sys_realtime.nsec = ts.tv_nsec;
#endif
#ifdef SIOCSHWTSTAMP
	} else if (request == SIOCSHWTSTAMP && s >= 0) {
#endif
#ifdef SIOCGHWTSTAMP
	} else if (request == SIOCGHWTSTAMP && s >= 0) {
		struct hwtstamp_config *ts_config;

		req = va_arg(ap, struct ifreq *);
		ts_config = (struct hwtstamp_config *)req->ifr_data;

		ts_config->flags = 0;
		ts_config->tx_type = HWTSTAMP_TX_ON;
		ts_config->rx_filter = HWTSTAMP_FILTER_ALL;
#endif
	} else if (request == PPS_GETCAP && fd == PPS_FD) {
		int *mode = va_arg(ap, int *);
		*mode = PPS_CAPTUREASSERT | PPS_TSFMT_TSPEC;
	} else if (request == PPS_GETPARAMS && fd == PPS_FD) {
		struct pps_kparams *params = va_arg(ap, struct pps_kparams *);
		memset(params, 0, sizeof (*params));
		params->mode = PPS_CAPTUREASSERT | PPS_TSFMT_TSPEC;
	} else if (request == PPS_SETPARAMS && fd == PPS_FD) {
		struct pps_kparams *params = va_arg(ap, struct pps_kparams *);
		if (params->mode != (PPS_CAPTUREASSERT | PPS_TSFMT_TSPEC))
			ret = -1, errno = EINVAL;
	} else if (request == PPS_FETCH && fd == PPS_FD) {
		static double last_refclock_time = 0.0;
		static unsigned long seq = 0;
		struct pps_fdata *data = va_arg(ap, struct pps_fdata *);
		memset(&data->info, 0, sizeof (data->info));
		if (data->timeout.flags & PPS_TIME_INVALID ||
		    data->timeout.sec > 0 || data->timeout.nsec > 0) {
			double d, prev_shm_time = shm_refclock_time;
			while (prev_shm_time == shm_refclock_time) {
				d = ceil(network_time) - network_time + 0.001;
				usleep((d > 0.2 ? d : 0.2) * 1e6);
			}
		}
		if (shm_refclock_time > 0.0) {
			if (shm_refclock_time != last_refclock_time)
				seq++;
			last_refclock_time = shm_refclock_time;
			data->info.assert_sequence = seq;
			data->info.assert_tu.sec = shm_refclock_time;
			data->info.assert_tu.nsec = (shm_refclock_time - data->info.assert_tu.sec) * 1e9;
			data->info.assert_tu.sec += system_time_offset;
		}
	} else if (request == RTC_UIE_ON && fd == RTC_FD) {
		struct itimerspec it;

		if (rtc_timerfd)
			close(rtc_timerfd);
		rtc_timerfd = timerfd_create(CLOCK_MONOTONIC, 0);

		it.it_interval.tv_sec = 1;
		it.it_interval.tv_nsec = 0;
		it.it_value.tv_sec = 0;
		it.it_value.tv_nsec = (ceil(get_rtc_time()) - get_rtc_time() + 1e-6) * 1e9;
		normalize_timespec(&it.it_value);
		timerfd_settime(rtc_timerfd, 0, &it, NULL);
	} else if (request == RTC_UIE_OFF && fd == RTC_FD) {
		close(rtc_timerfd);
		rtc_timerfd = 0;
	} else if (request == RTC_RD_TIME && fd == RTC_FD) {
		struct rtc_time *rtc = va_arg(ap, struct rtc_time *);
		time_t t = (time_t)get_rtc_time() + system_time_offset;
		struct tm *tm = gmtime(&t);

		rtc->tm_sec = tm->tm_sec;
		rtc->tm_min = tm->tm_min;
		rtc->tm_hour = tm->tm_hour;
		rtc->tm_mday = tm->tm_mday;
		rtc->tm_mon = tm->tm_mon;
		rtc->tm_year = tm->tm_year;
		rtc->tm_wday = tm->tm_wday;
		rtc->tm_yday = tm->tm_yday;
		rtc->tm_isdst = tm->tm_isdst;
	} else if (request == RTC_SET_TIME && fd == RTC_FD) {
		struct rtc_time *rtc = va_arg(ap, struct rtc_time *);
		struct tm tm;

		tm.tm_sec = rtc->tm_sec;
		tm.tm_min = rtc->tm_min;
		tm.tm_hour = rtc->tm_hour;
		tm.tm_mday = rtc->tm_mday;
		tm.tm_mon = rtc->tm_mon;
		tm.tm_year = rtc->tm_year;
		tm.tm_isdst = 0;
		rtc_offset -= get_rtc_time() + system_time_offset - (timegm(&tm) + 0.5);
	} else {
		ret = -1;
		errno = EINVAL;
	}

	va_end(ap);
	return ret;
}

int getifaddrs(struct ifaddrs **ifap) {
	struct iface {
		struct ifaddrs ifaddrs;
		struct sockaddr_in addr, netmask, broadaddr;
		char name[16];
	} *ifaces;
	int i, j;
       
	ifaces = malloc(sizeof (struct iface) * (1 + subnets));

	ifaces[0].ifaddrs = (struct ifaddrs){
		.ifa_next = &ifaces[1].ifaddrs,
		.ifa_name = "lo",
		.ifa_flags = IFF_UP | IFF_LOOPBACK | IFF_RUNNING,
		.ifa_addr = (struct sockaddr *)&ifaces[0].addr,
		.ifa_netmask = (struct sockaddr *)&ifaces[0].netmask,
		.ifa_broadaddr = (struct sockaddr *)&ifaces[0].broadaddr
	};
	ifaces[0].addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	ifaces[0].netmask.sin_addr.s_addr = htonl(0xff000000);
	ifaces[0].broadaddr.sin_addr.s_addr = 0;

	for (i = 0, j = 1; i < subnets && j < 1 + subnets; i++) {
		if (i == unix_subnet)
			continue;
		ifaces[j].ifaddrs = (struct ifaddrs){
			.ifa_next = &ifaces[j + 1].ifaddrs,
			.ifa_flags = IFF_UP | IFF_BROADCAST | IFF_RUNNING,
			.ifa_addr = (struct sockaddr *)&ifaces[j].addr,
			.ifa_netmask = (struct sockaddr *)&ifaces[j].netmask,
			.ifa_broadaddr = (struct sockaddr *)&ifaces[j].broadaddr
		};
		ifaces[j].ifaddrs.ifa_name = ifaces[j].name;
		snprintf(ifaces[j].name, sizeof (ifaces[j].name), "eth%d", i);
		ifaces[j].addr.sin_addr.s_addr = htonl(NODE_ADDR(i, node));
		ifaces[j].netmask.sin_addr.s_addr = htonl(NETMASK);
		ifaces[j].broadaddr.sin_addr.s_addr = htonl(BROADCAST_ADDR(i));
		j++;
	}

	ifaces[j - 1].ifaddrs.ifa_next = NULL;

	for (i = 0; i < 1 + subnets; i++) {
		ifaces[i].addr.sin_family = AF_INET;
		ifaces[i].netmask.sin_family = AF_INET;
		ifaces[i].broadaddr.sin_family = AF_INET;
	}

	*ifap = (struct ifaddrs *)ifaces;
	return 0;
}

void freeifaddrs(struct ifaddrs *ifa) {
	free(ifa);
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
	struct Request_send req;
	struct sockaddr_un *sun;
	struct cmsghdr *cmsg;
	int i, s = get_socket_from_fd(sockfd), timestamping;

	if (s < 0) {
		assert(0);
		errno = EINVAL;
		return -1;
	}

	if (sockets[s].remote_node >= 0) {
		if (msg->msg_name) {
			errno = EISCONN;
			return -1;
		}
		req.subnet = sockets[s].iface >= IFACE_ETH0 ? sockets[s].iface - IFACE_ETH0 : unix_subnet;
		req.to = sockets[s].remote_node;
		assert(sockets[s].remote_port >= 0);
		req.dst_port = sockets[s].remote_port;
	} else {
		switch (sockets[s].domain) {
			case AF_INET:
			case AF_INET6:
				if (!get_ip_target(s, msg->msg_name, msg->msg_namelen, &req.subnet,
						     &req.to, &req.dst_port)) {
					errno = EINVAL;
					return -1;
				}
				break;
			case AF_UNIX:
				sun = msg->msg_name;
				assert(sun && msg->msg_namelen > offsetof(struct sockaddr_un, sun_path) + 1);
				assert(sun->sun_family == AF_UNIX);
				req.subnet = unix_subnet;
				if (sscanf(sun->sun_path, "/clknetsim/unix/%u:%u",
					   &req.to, &req.dst_port) != 2) {
					errno = EINVAL;
					return -1;
				}
				req.to--;
				break;
			default:
				assert(0);
		}
	}

	switch (sockets[s].type) {
		case SOCK_DGRAM:
			req.type = MSG_TYPE_UDP_DATA;
			break;
		case SOCK_STREAM:
			assert(sockets[s].connected);
			req.type = MSG_TYPE_TCP_DATA;
			break;
		default:
			assert(0);
	}

	assert(req.src_port >= 0);
	req.src_port = sockets[s].port;

	assert(socket_in_subnet(s, req.subnet));

	for (req.len = 0, i = 0; i < msg->msg_iovlen; i++) {
		assert(req.len + msg->msg_iov[i].iov_len <= sizeof (req.data));
		memcpy(req.data + req.len, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
		req.len += msg->msg_iov[i].iov_len;
	}

	make_request(REQ_SEND, &req, offsetof(struct Request_send, data) + req.len, NULL, 0);

	write_pcap_packet(sockets[s].type, req.subnet, node, req.to,
			  req.src_port, req.dst_port, req.data, req.len);

	timestamping = sockets[s].time_stamping;
	for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR((struct msghdr *)msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMPING)
			memcpy(&timestamping, CMSG_DATA(cmsg), sizeof (timestamping));
	}

	if (timestamping & (SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_TX_HARDWARE)) {
		struct message *last_ts_msg = &sockets[s].last_ts_msg;

		assert(req.len <= sizeof (last_ts_msg->data));
		memcpy(last_ts_msg->data, req.data, req.len);
		last_ts_msg->len = req.len;
		last_ts_msg->subnet = req.subnet;
		last_ts_msg->to_from = req.to;
		last_ts_msg->port = req.dst_port;
	}

	return req.len;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
	struct msghdr msg;
	struct iovec iov;

	iov.iov_base = (void *)buf;
	iov.iov_len = len;

	msg.msg_name = (void *)dest_addr;
	msg.msg_namelen = addrlen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
	return sendmsg(sockfd, &msg, flags);
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
	return sendto(sockfd, buf, len, flags, NULL, 0);
}

int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags,
#if !defined(__GLIBC_PREREQ) || !(__GLIBC_PREREQ(2, 20))
		const
#endif
		struct timespec *timeout) {
	ssize_t len;
	int i, n;

	assert(vlen > 0);
	len = recvmsg(sockfd, &msgvec[0].msg_hdr, flags);
	if (len < 0)
		return -1;
	msgvec[0].msg_len = len;

	if (recv_multiply <= 1 || vlen <= 1)
		return 1;

	n = random() % recv_multiply + 1;
	if (n > vlen)
		n = vlen;

	for (i = 1; i < n; i++) {
		struct msghdr *src = &msgvec[0].msg_hdr, *dst = &msgvec[i].msg_hdr;
		if (dst->msg_name) {
			memcpy(dst->msg_name, src->msg_name, src->msg_namelen);
			dst->msg_namelen = src->msg_namelen;
		}
		assert(dst->msg_iovlen == 1 && dst->msg_iov[0].iov_len >= len);
		memcpy(dst->msg_iov[0].iov_base, src->msg_iov[0].iov_base, len);
		if (dst->msg_control) {
			assert(dst->msg_controllen >= src->msg_controllen);
			memcpy(dst->msg_control, src->msg_control, src->msg_controllen);
			dst->msg_controllen = src->msg_controllen;
		}
		dst->msg_flags = src->msg_flags;
		msgvec[i].msg_len = msgvec[0].msg_len;
	}

	return n;
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
	struct message *last_ts_msg = NULL;
	struct Reply_recv rep;
	struct cmsghdr *cmsg;
	int msglen, cmsglen, s = get_socket_from_fd(sockfd);

	if (sockfd == clknetsim_fd)
		return _recvmsg(sockfd, msg, flags);

	assert(s >= 0);

	if (sockets[s].last_ts_msg.len && flags & MSG_ERRQUEUE) {
		/* last message looped back to the error queue */

		last_ts_msg = &sockets[s].last_ts_msg;

		msg->msg_flags = MSG_ERRQUEUE;

		assert(sockets[s].type == SOCK_DGRAM);
		rep.type = MSG_TYPE_UDP_DATA;
		rep.subnet = last_ts_msg->subnet;
		rep.from = last_ts_msg->to_from;
		rep.src_port = last_ts_msg->port;
		rep.dst_port = sockets[s].port;

		/* put the message in an Ethernet frame */
		rep.len = generate_eth_frame(sockets[s].type, last_ts_msg->subnet,
					     node, last_ts_msg->to_from,
					     sockets[s].port, last_ts_msg->port,
					     last_ts_msg->data, last_ts_msg->len,
					     rep.data, sizeof (rep.data));

		last_ts_msg->len = 0;
	} else if (sockets[s].buffer.len > 0) {
		switch (sockets[s].type) {
			case SOCK_STREAM:
				assert(sockets[s].remote_node != -1);
				rep.type = MSG_TYPE_TCP_DATA;
				break;
			case SOCK_DGRAM:
				rep.type = MSG_TYPE_UDP_DATA;
				break;
			default:
				assert(0);
		}

		assert(sockets[s].buffer.len <= sizeof (rep.data));

		memcpy(rep.data, sockets[s].buffer.data, sockets[s].buffer.len);
		rep.subnet = sockets[s].buffer.subnet;
		rep.from = sockets[s].buffer.to_from;
		rep.src_port = sockets[s].buffer.port;
		rep.dst_port = sockets[s].port;
		rep.len = sockets[s].buffer.len;

		sockets[s].buffer.len = 0;
	} else {
		make_request(REQ_RECV, NULL, 0, &rep, sizeof (rep));

		switch (rep.type) {
			case MSG_TYPE_NO_MSG:
				errno = EWOULDBLOCK;
				return -1;
			case MSG_TYPE_UDP_DATA:
				assert(sockets[s].type == SOCK_DGRAM);
				break;
			case MSG_TYPE_TCP_DATA:
			case MSG_TYPE_TCP_DISCONNECT:
				assert(sockets[s].type == SOCK_STREAM);
				assert(sockets[s].remote_node >= 0);
				assert(sockets[s].remote_port >= 0);

				if (!sockets[s].connected) {
					errno = ENOTCONN;
					return -1;
				}
				if (rep.type == MSG_TYPE_TCP_DISCONNECT) {
					assert(rep.len == 0);
					sockets[s].connected = 0;
				}
				break;
			default:
				assert(0);
		}

		write_pcap_packet(sockets[s].type, rep.subnet, rep.from, node,
				  rep.src_port, rep.dst_port, rep.data, rep.len);
	}

	assert(socket_in_subnet(s, rep.subnet));
	assert(sockets[s].port == rep.dst_port);
	assert(sockets[s].remote_port == -1 || sockets[s].remote_port == rep.src_port);

	if (msg->msg_name) {
		set_sockaddr(sockets[s].domain, rep.subnet, rep.from, rep.src_port,
			     msg->msg_name, &msg->msg_namelen);
	}

	assert(msg->msg_iovlen == 1);
	msglen = msg->msg_iov[0].iov_len < rep.len ? msg->msg_iov[0].iov_len : rep.len;
	memcpy(msg->msg_iov[0].iov_base, rep.data, msglen);

	if (sockets[s].type == SOCK_STREAM) {
		if (msglen < rep.len) {
			sockets[s].buffer.len = rep.len - msglen;
			assert(sockets[s].buffer.len <= sizeof (sockets[s].buffer.data));
			memcpy(sockets[s].buffer.data, rep.data + msglen, rep.len - msglen);
			sockets[s].buffer.subnet = rep.subnet;
			sockets[s].buffer.to_from = rep.from;
			sockets[s].buffer.port = rep.src_port;
		} else {
			sockets[s].buffer.len = 0;
		}
	}

	cmsglen = 0;

	if (sockets[s].pkt_info && sockets[s].domain == AF_INET) {
		struct in_pktinfo ipi;

		cmsglen = CMSG_SPACE(sizeof (ipi));
		assert(msg->msg_control && msg->msg_controllen >= cmsglen);

		cmsg = CMSG_FIRSTHDR(msg);
		memset(cmsg, 0, sizeof (*cmsg));
		cmsg->cmsg_level = IPPROTO_IP;
		cmsg->cmsg_type = IP_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof (ipi));

		memset(&ipi, 0, sizeof (ipi));
		ipi.ipi_spec_dst.s_addr = htonl(NODE_ADDR(rep.subnet, node));
		ipi.ipi_addr.s_addr = ipi.ipi_spec_dst.s_addr;
		ipi.ipi_ifindex = rep.subnet + 1;

		memcpy(CMSG_DATA(cmsg), &ipi, sizeof (ipi));
	} else if (sockets[s].pkt_info && sockets[s].domain == AF_INET6) {
		struct in6_pktinfo ipi;

		cmsglen = CMSG_SPACE(sizeof (ipi));
		assert(msg->msg_control && msg->msg_controllen >= cmsglen);

		cmsg = CMSG_FIRSTHDR(msg);
		memset(cmsg, 0, sizeof (*cmsg));
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof (ipi));

		memset(&ipi, 0, sizeof (ipi));
		memcpy(ipi.ipi6_addr.s6_addr, IP6_NET, 14);
		ipi.ipi6_addr.s6_addr[14] = rep.subnet;
		ipi.ipi6_addr.s6_addr[15] = node + 1;
		ipi.ipi6_ifindex = rep.subnet + 1;

		memcpy(CMSG_DATA(cmsg), &ipi, sizeof (ipi));
	}

#ifdef SO_TIMESTAMPING
	if (last_ts_msg ||
	    (sockets[s].time_stamping & (SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_RX_HARDWARE) &&
	     !(flags & MSG_ERRQUEUE))) {
		struct timespec ts;

		/* don't use CMSG_NXTHDR as it's buggy in glibc */
		cmsg = (struct cmsghdr *)((char *)CMSG_FIRSTHDR(msg) + cmsglen);
		cmsglen += CMSG_SPACE(3 * sizeof (ts));
		assert(msg->msg_control && msg->msg_controllen >= cmsglen);

		memset(cmsg, 0, CMSG_SPACE(3 * sizeof (ts)));
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_TIMESTAMPING;
		cmsg->cmsg_len = CMSG_LEN(3 * sizeof (ts));

		if (sockets[s].time_stamping & SOF_TIMESTAMPING_SOFTWARE) {
			clock_gettime(CLOCK_REALTIME, &ts);
			memcpy((struct timespec *)CMSG_DATA(cmsg), &ts, sizeof (ts));
		}
		if (sockets[s].time_stamping & SOF_TIMESTAMPING_RAW_HARDWARE) {
			clock_gettime(timestamping > 1 ? REFCLK_ID : CLOCK_REALTIME, &ts);
			if (!(flags & MSG_ERRQUEUE))
				add_to_timespec(&ts, -(8 * (msglen + 42 + 4) / (1e6 * link_speed)));

			memcpy((struct timespec *)CMSG_DATA(cmsg) + 2, &ts, sizeof (ts));

#ifdef SCM_TIMESTAMPING_PKTINFO
			if (!(flags & MSG_ERRQUEUE) &&
			    (sockets[s].time_stamping & SOF_TIMESTAMPING_OPT_PKTINFO) ==
			    SOF_TIMESTAMPING_OPT_PKTINFO) {
				struct scm_ts_pktinfo tpi;

				cmsg = (struct cmsghdr *)((char *)CMSG_FIRSTHDR(msg) + cmsglen);
				cmsglen += CMSG_SPACE(sizeof (tpi));
				assert(msg->msg_control && msg->msg_controllen >= cmsglen);
				cmsg->cmsg_level = SOL_SOCKET;
				cmsg->cmsg_type = SCM_TIMESTAMPING_PKTINFO;
				cmsg->cmsg_len = CMSG_LEN(sizeof (tpi));

				memset(&tpi, 0, sizeof (tpi));
				tpi.if_index = rep.subnet + 1;
				tpi.pkt_length = msglen + 42;

				memcpy(CMSG_DATA(cmsg), &tpi, sizeof (tpi));
			}
#endif
		}
	}
#endif
	msg->msg_controllen = cmsglen;

	return msglen;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
	ssize_t ret;
	struct msghdr msg;
	struct iovec iov;

	iov.iov_base = (void *)buf;
	iov.iov_len = len;

	/* needed for compatibility with old glibc recvmsg() */
	memset(&msg, 0, sizeof (msg));

	msg.msg_name = (void *)src_addr;
	msg.msg_namelen = *addrlen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;

	ret = recvmsg(sockfd, &msg, flags);
	*addrlen = msg.msg_namelen;

	return ret;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
	union {
		struct sockaddr_in sin;
		struct sockaddr_un sun;
	} sa;
	socklen_t addrlen = sizeof (sa);

	return recvfrom(sockfd, buf, len, flags, (struct sockaddr *)&sa, &addrlen);
}

ssize_t __recv_chk(int fd, void *buf, size_t len, size_t buflen, int flags) {
	return recv(fd, buf, len, flags);
}

static int timer_create_(clockid_t which_clock, struct sigevent *timer_event_spec, timer_t *created_timer_id) {
	int t;

	assert(which_clock == CLOCK_REALTIME && timer_event_spec == NULL);

	t = get_free_timer();
	if (t < 0) {
		assert(0);
		errno = ENOMEM;
		return -1;
	}

	timers[t].used = 1;
	timers[t].armed = 0;
	timers[t].type = TIMER_TYPE_SIGNAL;
	timers[t].fd_flags = 0;
	timers[t].expired = 0;
	timers[t].clock_id = which_clock;
	*created_timer_id = get_timerid(t);

	return 0;
}

int timer_create(clockid_t which_clock, struct sigevent *timer_event_spec, timer_t *created_timer_id) {
	return timer_create_(which_clock, timer_event_spec, created_timer_id);
}

static int timer_delete_(timer_t timerid) {
	int t = get_timer_from_id(timerid);

	if (t < 0) {
		errno = EINVAL;
		return -1;
	}

	timers[t].used = 0;

	return 0;
}

int timer_delete(timer_t timerid) {
	return timer_delete_(timerid);
}

static int timer_settime_(timer_t timerid, int flags, const struct itimerspec *value, struct itimerspec *ovalue) {
	int t = get_timer_from_id(timerid);

	if (t < 0) {
		errno = EINVAL;
		return -1;
	}

	assert(value && ovalue == NULL &&
	       (flags == 0 || (flags == TIMER_ABSTIME && timers[t].clock_id == CLOCK_MONOTONIC)));

	if (value->it_value.tv_sec || value->it_value.tv_nsec) {
		timers[t].armed = 1;
		timers[t].expired = 0;
		timers[t].timeout = timespec_to_time(&value->it_value, 0);
		if (!(flags & TIMER_ABSTIME))
			timers[t].timeout += get_monotonic_time();
		timers[t].interval = timespec_to_time(&value->it_interval, 0);
	} else {
		timers[t].armed = 0;
	}

	return 0;
}

int timer_settime(timer_t timerid, int flags, const struct itimerspec *value, struct itimerspec *ovalue) {
	return timer_settime_(timerid, flags, value, ovalue);
}

int timer_gettime_(timer_t timerid, struct itimerspec *value) {
	double timeout;
	int t = get_timer_from_id(timerid);

	if (t < 0) {
		errno = EINVAL;
		return -1;
	}

	if (timers[t].armed) {
		timeout = timers[t].timeout - get_monotonic_time();
		time_to_timespec(timeout, &value->it_value);
	} else {
		value->it_value.tv_sec = 0;
		value->it_value.tv_nsec = 0;
	}
	time_to_timespec(timers[t].interval, &value->it_interval);

	return 0;
}

int timer_gettime(timer_t timerid, struct itimerspec *value) {
	return timer_gettime_(timerid, value);
}

#ifndef CLKNETSIM_DISABLE_ITIMER
int setitimer(__itimer_which_t which, const struct itimerval *new_value, struct itimerval *old_value) {
	struct itimerspec timerspec;

	assert(which == ITIMER_REAL && old_value == NULL);

	if (get_timer_from_id(itimer_real_id) < 0)
		timer_create(CLOCK_REALTIME, NULL, &itimer_real_id);

	timerspec.it_interval.tv_sec = new_value->it_interval.tv_sec;
	timerspec.it_interval.tv_nsec = new_value->it_interval.tv_usec * 1000;
	timerspec.it_value.tv_sec = new_value->it_value.tv_sec;
	timerspec.it_value.tv_nsec = new_value->it_value.tv_usec * 1000;

	return timer_settime(itimer_real_id, 0, &timerspec, NULL);
}

int getitimer(__itimer_which_t which, struct itimerval *curr_value) {
	struct itimerspec timerspec;

	assert(which == ITIMER_REAL);

	if (timer_gettime(itimer_real_id, &timerspec))
		return -1;

	curr_value->it_interval.tv_sec = timerspec.it_interval.tv_sec;
	curr_value->it_interval.tv_usec = timerspec.it_interval.tv_nsec / 1000;
	curr_value->it_value.tv_sec = timerspec.it_value.tv_sec;
	curr_value->it_value.tv_usec = timerspec.it_value.tv_nsec / 1000;

	return 0;
}
#endif

int timerfd_create(int clockid, int flags) {
	int t;

	assert((clockid == CLOCK_REALTIME || clockid == CLOCK_MONOTONIC) && !(flags & ~TFD_NONBLOCK));

	t = get_free_timer();
	if (t < 0) {
		assert(0);
		errno = ENOMEM;
		return -1;
	}

	timers[t].used = 1;
	timers[t].armed = 0;
	timers[t].type = TIMER_TYPE_FD;
	timers[t].fd_flags = flags;
	timers[t].expired = 0;
	timers[t].clock_id = clockid;

	return get_timerfd(t);
}

int timerfd_settime(int fd, int flags, const struct itimerspec *new_value, struct itimerspec *old_value) {
	if (flags == TFD_TIMER_ABSTIME)
		flags = TIMER_ABSTIME;
	else
		assert(!flags);

	return timer_settime_(get_timerid(get_timer_from_fd(fd)), flags, new_value, old_value);
}

int timerfd_gettime(int fd, struct itimerspec *curr_value) {
	return timer_gettime_(get_timerid(get_timer_from_fd(fd)), curr_value);
}

int shmget(key_t key, size_t size, int shmflg) {
	if (fuzz_mode)
		return _shmget(key, size, shmflg);

	if (key >= SHM_KEY && key < SHM_KEY + SHM_REFCLOCKS)
		return key;

	return -1;
}

void *shmat(int shmid, const void *shmaddr, int shmflg) {
	if (fuzz_mode)
		return _shmat(shmid, shmaddr, shmflg);

	assert(shmid >= SHM_KEY && shmid < SHM_KEY + SHM_REFCLOCKS);

	if (shm_refclocks < shmid - SHM_KEY + 1)
		shm_refclocks = shmid - SHM_KEY + 1;
	memset(&shm_time[shmid - SHM_KEY], 0, sizeof (shm_time[0]));
	shm_time[shmid - SHM_KEY].mode = 1;
	shm_time[shmid - SHM_KEY].precision = -20;

	/* don't wait for select() with starting of the refclock generator */
	fill_refclock_sample();

	return &shm_time[shmid - SHM_KEY];
}

int shmdt(const void *shmaddr) {
	assert(shmaddr >= (void *)&shm_time[0] && shmaddr < (void *)&shm_time[SHM_REFCLOCKS]);
	return 0;
}

int uname(struct utsname *buf) {
	memset(buf, 0, sizeof (*buf));
	sprintf(buf->sysname, "Linux (clknetsim)");
	sprintf(buf->release, "4.19");
	return 0;
}

int gethostname(char *name, size_t len) {
	snprintf(name, len, "clknetsim-node%d", node + 1);
	return 0;
}

void openlog(const char *ident, int option, int facility) {
}

void __syslog_chk(int priority, int flag, const char *format, ...) {
	va_list ap;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

void __syslog_chkieee128(int priority, int flag, const char *format, ...) {
	va_list ap;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

void syslog(int priority, const char *format, ...) {
	va_list ap;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

void closelog(void) {
}

#ifndef CLKNETSIM_DISABLE_SYSCALL
long syscall(long number, ...) {
	va_list ap;
	long r;
	struct timex *timex;
	clockid_t clock_id;

	va_start(ap, number);
	switch (number) {
#ifdef __NR_clock_adjtime
		case __NR_clock_adjtime:
			clock_id = va_arg(ap, clockid_t);
			timex = va_arg(ap, struct timex *);
			r = clock_adjtime(clock_id, timex);
			break;
#endif
#ifdef __NR_getrandom
		case __NR_getrandom:
			if (1) {
				void *buf = va_arg(ap, void *);
				size_t length = va_arg(ap, size_t);
				r = read(URANDOM_FD, buf, length);
			}
			break;
#endif
		default:
			assert(0);
	}
	va_end(ap);

	return r;
}
#endif

ssize_t getrandom(void *buf, size_t length, unsigned int flags) {
	return read(URANDOM_FD, buf, length);
}

void srandom(unsigned int seed) {
	FILE *f;

	/* override the seed to the fixed seed if set or make it truly
	   random in case it's based on the simulated time */
	if (random_seed) {
		seed = random_seed + node;
	} else if ((f = _fopen("/dev/urandom", "r"))) {
		if (fread(&seed, sizeof (seed), 1, f) != 1)
			;
		fclose(f);
	}
	_srandom(seed);
}

struct passwd *getpwnam(const char *name) {
	static struct passwd pw = {
		.pw_name = "",
		.pw_passwd = "",
		.pw_uid = 0,
		.pw_gid = 0,
		.pw_gecos = "",
		.pw_dir = "",
		.pw_shell = ""
	};

	return &pw;
}

int initgroups(const char *user, gid_t group) {
	return 0;
}

int setgroups(size_t size, const gid_t *list) {
	return 0;
}

uid_t getuid(void) {
	return 0;
}

uid_t geteuid(void) {
	return 0;
}

gid_t getgid(void) {
	return 0;
}

gid_t getegid(void) {
	return 0;
}

int setegid(gid_t gid) {
	return 0;
}

int setgid(gid_t gid) {
	return 0;
}

int seteuid(uid_t uid) {
	return 0;
}

int setuid(uid_t uid) {
	return 0;
}

int cap_set_proc() {
	return 0;
}

static struct addrinfo *get_addrinfo(int family, uint32_t addr, int port, int type, struct addrinfo *next) {
	struct sockaddr_in6 *sin6;
	struct sockaddr_in *sin;
	struct addrinfo *r;
	socklen_t len;

	r = malloc(sizeof *r);
	memset(r, 0, sizeof *r);

	if (family == 6) {
		sin6 = malloc(sizeof *sin6);
		len = sizeof (*sin6);
		set_sockaddr(AF_INET6, SUBNET_FROM_ADDR(addr), NODE_FROM_ADDR(addr), port,
			     (struct sockaddr *)sin6, &len);
		r->ai_family = AF_INET6;
		r->ai_socktype = type;
		r->ai_addrlen = sizeof *sin6;
		r->ai_addr = (struct sockaddr *)sin6;
	} else {
		sin = malloc(sizeof *sin);
		sin->sin_family = AF_INET;
		sin->sin_port = htons(port);
		sin->sin_addr.s_addr = htonl(addr);
		r->ai_family = AF_INET;
		r->ai_socktype = type;
		r->ai_addrlen = sizeof *sin;
		r->ai_addr = (struct sockaddr *)sin;
	}

	r->ai_next = next;

	return r;
}

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints,
		struct addrinfo **res) {
	int family = ip_family, port = 0, type = SOCK_DGRAM;
	struct in_addr addr;

	if (hints) {
		if (hints->ai_family == AF_INET)
		       family = 4;
		else if (hints->ai_family == AF_INET6)
		       family = 6;
		else if (hints->ai_family != AF_UNSPEC)
			return EAI_NONAME;

		if (hints->ai_socktype != SOCK_STREAM && hints->ai_socktype != SOCK_DGRAM &&
		    hints->ai_socktype != 0)
			return EAI_NONAME;

		if (hints->ai_socktype == SOCK_STREAM)
			type = SOCK_STREAM;
	}

	if (service) {
		if (strcmp(service, "ntp") == 0)
			port = 123;
		else if (service[0] >= '0' && service[0] <= '9')
			port = atoi(service);
		else
			return EAI_NONAME;
	}

	if (node == NULL) {
		assert(ip_family != 6);
		*res = get_addrinfo(4, INADDR_ANY, port, type, NULL);
	} else if (inet_aton(node, &addr)) {
		*res = get_addrinfo(4, ntohl(addr.s_addr), port, type, NULL);
	} else if ((strlen(node) > 4 && strcmp(node + strlen(node) - 4, ".clk") == 0) ||
		   (strlen(node) > 5 && strcmp(node + strlen(node) - 5, ".clk.") == 0)) {
		const char *s = strstr(node, ".net");
		int subnet;

		if (s == NULL)
			return EAI_NONAME;

		subnet = atoi(s + 4) - 1;

		if (strncmp(node, "nodes-", 6) == 0) {
			s = node + 5;
			*res = NULL;
			do {
				*res = get_addrinfo(family, NODE_ADDR(subnet, atoi(s + 1) - 1),
						    port, type, *res);
				s = strchr(s + 1, '-');
			} while (s);
		} else if (strncmp(node, "node", 4) == 0) {
			*res = get_addrinfo(family, NODE_ADDR(subnet, atoi(node + 4) - 1),
					    port, type, NULL);
		} else {
			return EAI_NONAME;
		}
	} else {
		return EAI_NONAME;
	}

	return 0;
}

void freeaddrinfo(struct addrinfo *res) {
	if (res->ai_next)
		freeaddrinfo(res->ai_next);
	free(res->ai_addr);
	free(res);
}

int getnameinfo(const struct sockaddr *addr, socklen_t addrlen,
		char *host, socklen_t hostlen,
		char *serv, socklen_t servlen, int flags) {
	const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
	int node, subnet;

	if (addrlen < sizeof *sin || sin->sin_family != AF_INET)
		return EAI_NONAME;

	assert(!(flags & NI_NOFQDN));

	if (host && hostlen > 0) {
		if (flags & NI_NUMERICHOST) {
			assert(addr->sa_family == AF_INET);
			if (!inet_ntop(AF_INET, &((struct sockaddr_in *)addr)->sin_addr,
				       host, hostlen))
				return EAI_OVERFLOW;
		} else {
			node = NODE_FROM_ADDR(ntohl(sin->sin_addr.s_addr));
			subnet = SUBNET_FROM_ADDR(ntohl(sin->sin_addr.s_addr));
			if (subnet < 0 || subnet > 100) {
				assert(flags & NI_NAMEREQD);
				return EAI_NONAME;
			}
			if (snprintf(host, hostlen, "node%d.net%d.clk",
				     node + 1, subnet + 1) >= hostlen)
				return EAI_OVERFLOW;
		}
	}

	if (serv && servlen > 0) {
		if (flags & NI_NUMERICSERV) {
			assert(addr->sa_family == AF_INET);
			if (snprintf(serv, servlen, "%d",
				     ntohs(((struct sockaddr_in *)addr)->sin_port)) >= servlen)
				return EAI_OVERFLOW;
		} else {
			switch (ntohs(sin->sin_port)) {
				case 123:
					if (snprintf(serv, servlen, "ntp") >= servlen)
						return EAI_OVERFLOW;
					break;
				default:
					if (snprintf(serv, servlen, "%u",
						     ntohs(sin->sin_port)) >= servlen)
						return EAI_OVERFLOW;
			}
		}
	}

	return 0;
}

struct hostent *gethostbyname(const char *name) {
	h_errno = HOST_NOT_FOUND;
	return NULL;
}

struct hostent *gethostbyaddr(const void *addr, socklen_t len, int type) {
	h_errno = HOST_NOT_FOUND;
	return NULL;
}
