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
#include <sys/utsname.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <sys/un.h>
#include <unistd.h>
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pwd.h>
#include <stdarg.h>
#include <signal.h>
#include <ifaddrs.h>
#include <linux/types.h>
#include <linux/ethtool.h>
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

#define PTP_PRIMARY_MCAST_ADDR 0xe0000181 /* 224.0.1.129 */
#define PTP_PDELAY_MCAST_ADDR 0xe000006b /* 224.0.0.107 */

#define REFCLK_FD 1000
#define REFCLK_ID ((~(clockid_t)REFCLK_FD << 3) | 3)
#define REFCLK_PHC_INDEX 0
#define SYSCLK_FD 1001
#define SYSCLK_CLOCKID ((~(clockid_t)SYSCLK_FD << 3) | 3)
#define SYSCLK_PHC_INDEX 1

#define MAX_SOCKETS 20
#define BASE_SOCKET_FD 100
#define BASE_SOCKET_DEFAULT_PORT 60000

#define MAX_TIMERS 40
#define BASE_TIMER_ID 0xC1230123
#define BASE_TIMER_FD 200

#define URANDOM_FILE (void *)0xD1230123

static FILE *(*_fopen)(const char *path, const char *mode);
static size_t (*_fread)(void *ptr, size_t size, size_t nmemb, FILE *stream);
static int (*_fileno)(FILE *stream);
static int (*_fclose)(FILE *fp);
static int (*_fcntl)(int fd, int cmd, ...);
static int (*_open)(const char *pathname, int flags);
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
static int initialized = 0;
static int clknetsim_fd;
static int precision_hack = 1;
static unsigned int random_seed = 0;
static int recv_multiply = 1;
static int timestamping = 1;

enum {
	IFACE_NONE = 0,
	IFACE_LO,
	IFACE_ALL,
	IFACE_ETH0,
};

struct message {
	char data[MAX_PACKET_SIZE];
	unsigned int len;
	unsigned int subnet;
	unsigned int to;
	unsigned int port;
};

struct socket {
	int used;
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

static double real_time = 0.0;
static double monotonic_time = 0.0;
static double network_time = 0.0;
static int local_time_valid = 0;

static time_t system_time_offset = 1262304000; /* 2010-01-01 0:00 UTC */

#define TIMER_TYPE_SIGNAL 1
#define TIMER_TYPE_FD 2

struct timer {
	int used;
	int armed;
	int type;
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
static int refclock_offsets_used = REPLY_GETREFOFFSETS_SIZE;

static void make_request(int request_id, const void *request_data, int reqlen, void *reply, int replylen);

__attribute__((constructor))
static void init(void) {
	struct Request_register req;
	struct Reply_register rep;
	struct sockaddr_un s = {AF_UNIX, "clknetsim.sock"};
	const char *env;
	unsigned int connect_retries = 100; /* 10 seconds */

	if (initialized)
		return;

	_fopen = (FILE *(*)(const char *path, const char *mode))dlsym(RTLD_NEXT, "fopen");
	_fread = (size_t (*)(void *ptr, size_t size, size_t nmemb, FILE *stream))dlsym(RTLD_NEXT, "fread");
	_fileno = (int (*)(FILE *stream))dlsym(RTLD_NEXT, "fileno");
	_fclose = (int (*)(FILE *fp))dlsym(RTLD_NEXT, "fclose");
	_fcntl = (int (*)(int fd, int cmd, ...))dlsym(RTLD_NEXT, "fcntl");
	_open = (int (*)(const char *pathname, int flags))dlsym(RTLD_NEXT, "open");
	_close = (int (*)(int fd))dlsym(RTLD_NEXT, "close");
	_socket = (int (*)(int domain, int type, int protocol))dlsym(RTLD_NEXT, "socket");
	_connect = (int (*)(int sockfd, const struct sockaddr *addr, socklen_t addrlen))dlsym(RTLD_NEXT, "connect");
	_recvmsg = (ssize_t (*)(int sockfd, struct msghdr *msg, int flags))dlsym(RTLD_NEXT, "recvmsg");
	_send = (ssize_t (*)(int sockfd, const void *buf, size_t len, int flags))dlsym(RTLD_NEXT, "send");
	_usleep = (int (*)(useconds_t usec))dlsym(RTLD_NEXT, "usleep");
	_srandom = (void (*)(unsigned int seed))dlsym(RTLD_NEXT, "srandom");
	_shmget = (int (*)(key_t key, size_t size, int shmflg))dlsym(RTLD_NEXT, "shmget");
	_shmat = (void *(*)(int shmid, const void *shmaddr, int shmflg))dlsym(RTLD_NEXT, "shmat");

	env = getenv("CLKNETSIM_START_DATE");
	if (env)
		system_time_offset = atol(env);

	env = getenv("CLKNETSIM_RANDOM_SEED");
	if (env)
		random_seed = atoi(env);

	env = getenv("CLKNETSIM_RECV_MULTIPLY");
	if (env)
		recv_multiply = atoi(env);

	env = getenv("CLKNETSIM_TIMESTAMPING");
	if (env)
		timestamping = atoi(env);

	if (fuzz_init()) {
		node = 0;
		subnets = 1;
		initialized = 1;
		return;
	}

	env = getenv("CLKNETSIM_NODE");
	if (!env) {
		fprintf(stderr, "clknetsim: CLKNETSIM_NODE variable not set.\n");
		exit(1);
	}
	node = atoi(env) - 1;

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

	initialized = 1;

	req.node = node;
	make_request(REQ_REGISTER, &req, sizeof (req), &rep, sizeof (rep));

	subnets = rep.subnets;
}

__attribute__((destructor))
static void fini(void) {
	if (initialized)
		make_request(REQ_DEREGISTER, NULL, 0, NULL, 0);
}

static void make_request(int request_id, const void *request_data, int reqlen, void *reply, int replylen) {
	struct Request_packet request;
	int sent, received = 0;

	assert(initialized);

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
	if (refclock_offsets_used >= REPLY_GETREFOFFSETS_SIZE) {
		make_request(REQ_GETREFOFFSETS, NULL, 0, &refclock_offsets, sizeof (refclock_offsets));
		refclock_offsets_used = 0;
	}
	return refclock_offsets.offsets[refclock_offsets_used++];
}

static double get_refclock_time(void) {
	fetch_time();
	return network_time - get_refclock_offset();
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

	if (!shm_refclocks)
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
		case IFACE_NONE:
		case IFACE_ALL:
			return 1;
		default:
			return sockets[socket].iface - IFACE_ETH0 == subnet;
	}
}

static void get_target(int socket, uint32_t addr, unsigned int *subnet, unsigned int *node) {
	if (addr == PTP_PRIMARY_MCAST_ADDR || addr == PTP_PDELAY_MCAST_ADDR) {
		assert(sockets[socket].iface >= IFACE_ETH0);
		*subnet = sockets[socket].iface - IFACE_ETH0;
		*node = -1; /* multicast as broadcast */
	} else {
		*subnet = SUBNET_FROM_ADDR(addr);
		assert(*subnet >= 0 && *subnet < subnets);
		assert(socket_in_subnet(socket, *subnet));

		if (addr == BROADCAST_ADDR(*subnet))
			*node = -1; /* broadcast */
		else
			*node = NODE_FROM_ADDR(addr);
	}
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
		    (sockets[i].remote_node != -1 && sockets[i].remote_node != rep->from) ||
		    (sockets[i].remote_port && sockets[i].remote_port != rep->src_port))
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

int gettimeofday(struct timeval *tv, struct timezone *tz) {
	double time;

	time = get_real_time() + 0.5e-6;

	time_to_timeval(time, tv);
	tv->tv_sec += system_time_offset;

	/* chrony clock precision routine hack */
	if (precision_hack)
		tv->tv_usec += random() % 2;

	return 0;
}

int clock_gettime(clockid_t which_clock, struct timespec *tp) {
	double time;

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
	
	if (which_clock == CLOCK_REALTIME || which_clock == REFCLK_ID)
		tp->tv_sec += system_time_offset;

	/* ntpd clock precision routine hack */
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
	assert(tv);
	settime(timeval_to_time(tv, -system_time_offset));
	return 0;
}

int clock_settime(clockid_t which_clock, const struct timespec *tp) {
	assert(tp && which_clock == CLOCK_REALTIME);
	settime(timespec_to_time(tp, -system_time_offset));
	return 0;
}

int adjtimex(struct timex *buf) {
	struct Request_adjtimex req;
	struct Reply_adjtimex rep;

	if (buf->modes & ADJ_SETOFFSET)
		local_time_valid = 0;

	req.timex = *buf;
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

	if (writefds) {
		for (i = 0; i < nfds; i++) {
			if (!FD_ISSET(i, writefds))
				continue;
			s = get_socket_from_fd(i);
			if (s < 0 ||
			    (sockets[s].type == SOCK_STREAM && !sockets[s].connected))
				continue;
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

	req.read = 0;
	req._pad = 0;

	/* unknown reading fds are always ready (e.g. chronyd waiting
	   for name resolving notification, or OpenSSL waiting for
	   /dev/urandom) */
	if (readfds) {
		for (i = 0; i < nfds; i++) {
			if (!FD_ISSET(i, readfds))
				continue;
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

	assert((timeout && (timeout->tv_sec > 0 || timeout->tv_usec > 0)) ||
	       timer >= 0 || find_recv_socket(NULL) >= 0);

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
			recv_fd = s >= 0 ? get_socket_fd(s) : 0;

			/* fetch and drop the packet if no fd is waiting for it */
			if (!readfds || !recv_fd || !FD_ISSET(recv_fd, readfds)) {
				struct Reply_recv recv_rep;

				make_request(REQ_RECV, NULL, 0, &recv_rep, sizeof (recv_rep));
				if (rep.ret != REPLY_SELECT_BROADCAST)
					fprintf(stderr, "clknetsim: dropped packet of type %d from "
							"node %d on port %d in subnet %d\n",
							recv_rep.type, recv_rep.from + 1,
							recv_rep.dst_port, recv_rep.subnet + 1);

				goto try_again;
			}

			if (rep.type == MSG_TYPE_TCP_CONNECT &&
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
		if (recv_fd)
			FD_SET(recv_fd, readfds);
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
	assert(r == 0);

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
	init();

	return _fopen(path, mode);
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
	if (stream == URANDOM_FILE) {
		size_t i, l = size * nmemb;
		long r;

		assert(RAND_MAX >= 0xffffff);
		for (i = r = 0; i < l; i++) {
			if (i % 3)
				r >>= 8;
			else
				r = random();
			((unsigned char *)ptr)[i] = r;
		}

		return nmemb;
	}

	return _fread(ptr, size, nmemb, stream);
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

int open(const char *pathname, int flags) {
	int r;

	assert(REFCLK_PHC_INDEX == 0 && SYSCLK_PHC_INDEX == 1);
	if (!strcmp(pathname, "/dev/ptp0"))
		return REFCLK_FD;
	else if (!strcmp(pathname, "/dev/ptp1"))
		return SYSCLK_FD;

	r = _open(pathname, flags);
	assert(r < 0 || (r < BASE_SOCKET_FD && r < BASE_TIMER_FD));

	return r;
}

int close(int fd) {
	int t, s;

	if (fd == REFCLK_FD || fd == SYSCLK_FD) {
		return 0;
	} else if ((t = get_timer_from_fd(fd)) >= 0) {
		return timer_delete(get_timerid(t));
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

	if (domain != AF_INET || (type != SOCK_DGRAM && type != SOCK_STREAM)) {
		errno = EINVAL;
		return -1;
	}

	s = get_free_socket();
	if (s < 0) {
		assert(0);
		errno = ENOMEM;
		return -1;
	}

	memset(sockets + s, 0, sizeof (struct socket));
	sockets[s].used = 1;
	sockets[s].type = type;
	sockets[s].port = BASE_SOCKET_DEFAULT_PORT + s;
	sockets[s].remote_node = -1;

	return get_socket_fd(s);
}

int listen(int sockfd, int backlog) {
	int s = get_socket_from_fd(sockfd);

	if (s < 0 || sockets[s].type != SOCK_STREAM) {
		errno = EINVAL;
		return -1;
	}

	sockets[s].listening = 1;

	return 0;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	int s = get_socket_from_fd(sockfd), r;
	struct sockaddr_in *in;
	struct Reply_recv rep;

	if (s < 0 || sockets[s].type != SOCK_STREAM) {
		errno = EINVAL;
		return -1;
	}

	make_request(REQ_RECV, NULL, 0, &rep, sizeof (rep));
	assert(rep.type == MSG_TYPE_TCP_CONNECT);

	r = socket(AF_INET, SOCK_STREAM, 0);
	s = get_socket_from_fd(r);
	assert(s >= 0);

	sockets[s].port = rep.dst_port;
	sockets[s].iface = IFACE_ETH0 + rep.subnet;
	sockets[s].remote_node = rep.from;
	sockets[s].remote_port = rep.src_port;
	sockets[s].connected = 1;

	in = (struct sockaddr_in *)addr;
	assert(*addrlen >= sizeof (*in));
	*addrlen = sizeof (*in);
	in->sin_family = AF_INET;
	in->sin_port = htons(sockets[s].remote_port);
	in->sin_addr.s_addr = htonl(NODE_ADDR(sockets[s].iface - IFACE_ETH0, node));

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
	int s = get_socket_from_fd(sockfd), port;
	unsigned int node, subnet;
	uint32_t a;

	if (s < 0 || addr->sa_family != AF_INET) {
		errno = EINVAL;
		return -1;
	}

	port = ntohs(((const struct sockaddr_in *)addr)->sin_port);
	a = ntohl(((const struct sockaddr_in *)addr)->sin_addr.s_addr);

	get_target(s, a, &subnet, &node);

	sockets[s].iface = IFACE_ETH0 + subnet;
	sockets[s].remote_node = node;
	sockets[s].remote_port = port;

	if (sockets[s].type == SOCK_STREAM)
		send_msg_to_peer(s, MSG_TYPE_TCP_CONNECT);

	return 0;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	int s = get_socket_from_fd(sockfd), port;
	uint32_t a;

	if (s < 0 || addr->sa_family != AF_INET) {
		errno = EINVAL;
		return -1;
	}

	port = ntohs(((struct sockaddr_in *)addr)->sin_port);
	a = ntohl(((struct sockaddr_in *)addr)->sin_addr.s_addr);

	if (port)
		sockets[s].port = port;

	if (a == INADDR_ANY)
		sockets[s].iface = IFACE_ALL;
	else if (a == INADDR_LOOPBACK)
		sockets[s].iface = IFACE_LO;
	else {
		int subnet = SUBNET_FROM_ADDR(a);
		assert(subnet >= 0 && subnet < subnets);
		if (a == NODE_ADDR(subnet, node))
			sockets[s].iface = IFACE_ETH0 + subnet;
		else if (a == BROADCAST_ADDR(subnet)) {
			sockets[s].iface = IFACE_ETH0 + subnet;
			sockets[s].broadcast = 1;
		} else
			assert(0);
	}

	return 0;
}

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	int s = get_socket_from_fd(sockfd);
	uint32_t a;

	if (s < 0) {
		errno = EINVAL;
		return -1;
	}

	struct sockaddr_in *in;
	in = (struct sockaddr_in *)addr;
	assert(*addrlen >= sizeof (*in));
	*addrlen = sizeof (*in);
	in->sin_family = AF_INET;
	in->sin_port = htons(sockets[s].port);

	switch (sockets[s].iface) {
		case IFACE_NONE:
		case IFACE_ALL:
			a = INADDR_ANY;
			break;
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

	if (s < 0) {
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
	else if (level == IPPROTO_IP && optname == IP_PKTINFO && optlen == sizeof (int))
		sockets[s].pkt_info = !!(int *)optval;
#ifdef SO_TIMESTAMPING
	else if (level == SOL_SOCKET && optname == SO_TIMESTAMPING && optlen == sizeof (int)) {
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

	if (s < 0) {
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

int ioctl(int fd, unsigned long request, ...) {
	va_list ap;
	struct ifconf *conf;
	struct ifreq *req;
	int i, subnet, ret = 0, s = get_socket_from_fd(fd);

	va_start(ap, request);

	if (request == SIOCGIFCONF) {
		conf = va_arg(ap, struct ifconf *);
		assert(conf->ifc_len >= sizeof (struct ifreq) * (1 + subnets));
		conf->ifc_len = sizeof (struct ifreq) * (1 + subnets);
		sprintf(conf->ifc_req[0].ifr_name, "lo");
		((struct sockaddr_in*)&conf->ifc_req[0].ifr_addr)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		conf->ifc_req[0].ifr_addr.sa_family = AF_INET;

		for (i = 0; i < subnets; i++) {
			sprintf(conf->ifc_req[i + 1].ifr_name, "eth%d", i);
			((struct sockaddr_in*)&conf->ifc_req[i + 1].ifr_addr)->sin_addr.s_addr = htonl(NODE_ADDR(i, node));
			conf->ifc_req[i + 1].ifr_addr.sa_family = AF_INET;
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
			ethtool_cmd_speed_set(cmd, 100000);
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
		struct timespec ts;
		int i;

		if (sys_off->n_samples > PTP_MAX_SAMPLES)
			sys_off->n_samples = PTP_MAX_SAMPLES;

		clock_gettime(REFCLK_ID, &ts);
		for (i = 0; i < sys_off->n_samples; i++) {
			sys_off->ts[2 * i + 1].sec = ts.tv_sec;
			sys_off->ts[2 * i + 1].nsec = ts.tv_nsec;
		}

		clock_gettime(CLOCK_REALTIME, &ts);
		for (i = 0; i < sys_off->n_samples + 1; i++) {
			sys_off->ts[2 * i].sec = ts.tv_sec;
			sys_off->ts[2 * i].nsec = ts.tv_nsec;
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
		char name[11];
	} *ifaces;
	int i;
       
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

	for (i = 0; i < subnets; i++) {
		ifaces[i + 1].ifaddrs = (struct ifaddrs){
			.ifa_next = &ifaces[i + 2].ifaddrs,
			.ifa_flags = IFF_UP | IFF_BROADCAST | IFF_RUNNING,
			.ifa_addr = (struct sockaddr *)&ifaces[i + 1].addr,
			.ifa_netmask = (struct sockaddr *)&ifaces[i + 1].netmask,
			.ifa_broadaddr = (struct sockaddr *)&ifaces[i + 1].broadaddr
		};
		ifaces[i + 1].ifaddrs.ifa_name = ifaces[i + 1].name;
		snprintf(ifaces[i + 1].name, sizeof (ifaces[i + 1].name), "eth%d", i);
		ifaces[i + 1].addr.sin_addr.s_addr = htonl(NODE_ADDR(i, node));
		ifaces[i + 1].netmask.sin_addr.s_addr = htonl(NETMASK);
		ifaces[i + 1].broadaddr.sin_addr.s_addr = htonl(BROADCAST_ADDR(i));
	}

	ifaces[i].ifaddrs.ifa_next = NULL;

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
	struct sockaddr_in connected_sa, *sa;
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
		sa = &connected_sa;
		sa->sin_family = AF_INET;
		sa->sin_port = htons(sockets[s].remote_port);
		sa->sin_addr.s_addr = htonl(NODE_ADDR(sockets[s].iface - IFACE_ETH0,
					sockets[s].remote_node));
	} else {
		sa = msg->msg_name;
		assert(sa && msg->msg_namelen >= sizeof (struct sockaddr_in));
		assert(sa->sin_family == AF_INET);
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

	get_target(s, ntohl(sa->sin_addr.s_addr), &req.subnet, &req.to);
	req.src_port = sockets[s].port;
	req.dst_port = ntohs(sa->sin_port);
	assert(req.src_port && req.dst_port);

	for (req.len = 0, i = 0; i < msg->msg_iovlen; i++) {
		assert(req.len + msg->msg_iov[i].iov_len <= sizeof (req.data));
		memcpy(req.data + req.len, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
		req.len += msg->msg_iov[i].iov_len;
	}

	make_request(REQ_SEND, &req, offsetof(struct Request_send, data) + req.len, NULL, 0);

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
		last_ts_msg->to = req.to;
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
	struct sockaddr_in *sa;
	struct cmsghdr *cmsg;
	int msglen, cmsglen, s = get_socket_from_fd(sockfd);

	if (sockfd == clknetsim_fd)
		return _recvmsg(sockfd, msg, flags);

	assert(s >= 0);

	if (sockets[s].last_ts_msg.len && flags & MSG_ERRQUEUE) {
		uint32_t addr;
		uint16_t port;

		/* last message looped back to the error queue */

		last_ts_msg = &sockets[s].last_ts_msg;

		msg->msg_flags = MSG_ERRQUEUE;

		assert(sockets[s].type == SOCK_DGRAM);
		rep.type = MSG_TYPE_UDP_DATA;
		rep.subnet = last_ts_msg->subnet;
		rep.from = last_ts_msg->to;
		rep.src_port = last_ts_msg->port;
		rep.dst_port = sockets[s].port;

		addr = htonl(NODE_ADDR(rep.subnet, rep.from));
		port = htons(rep.src_port);

		/* put the message in an Ethernet frame */
		memset(rep.data, 0, 42);
		rep.data[12] = 0x08;
		rep.data[14] = 0x45;
		rep.data[23] = 17;
		memcpy(rep.data + 30, &addr, sizeof (addr));
		memcpy(rep.data + 36, &port, sizeof (port));

		assert(last_ts_msg->len + 42 <= sizeof (rep.data));
		memcpy(rep.data + 42, last_ts_msg->data, last_ts_msg->len);

		rep.len = 42 + last_ts_msg->len;

		last_ts_msg->len = 0;
	} else if (sockets[s].buffer.len > 0) {
		assert(sockets[s].type == SOCK_STREAM && sockets[s].remote_node != -1);
		assert(sockets[s].buffer.len <= sizeof (rep.data));

		memcpy(rep.data, sockets[s].buffer.data, sockets[s].buffer.len);
		rep.type = MSG_TYPE_TCP_DATA;
		rep.subnet = sockets[s].iface - IFACE_ETH0;
		rep.from = sockets[s].remote_node;
		rep.src_port = sockets[s].remote_port;
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
				assert(sockets[s].remote_port && sockets[s].remote_node != -1);

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
	}

	assert(socket_in_subnet(s, rep.subnet));
	assert(sockets[s].port == rep.dst_port);
	assert(!sockets[s].remote_port || sockets[s].remote_port == rep.src_port);

	if (msg->msg_name) {
		assert(msg->msg_namelen >= sizeof (struct sockaddr_in));

		sa = msg->msg_name;
		sa->sin_family = AF_INET;
		sa->sin_port = htons(rep.src_port);
		sa->sin_addr.s_addr = htonl(NODE_ADDR(rep.subnet, rep.from));
		msg->msg_namelen = sizeof (struct sockaddr_in);
	}

	assert(msg->msg_iovlen == 1);
	msglen = msg->msg_iov[0].iov_len < rep.len ? msg->msg_iov[0].iov_len : rep.len;
	memcpy(msg->msg_iov[0].iov_base, rep.data, msglen);

	if (sockets[s].type == SOCK_STREAM) {
	       if (msglen < rep.len) {
		       sockets[s].buffer.len = rep.len - msglen;
		       assert(sockets[s].buffer.len <= sizeof (sockets[s].buffer.data));
		       memcpy(sockets[s].buffer.data, rep.data + msglen, rep.len - msglen);
	       } else {
		       sockets[s].buffer.len = 0;
	       }
	}

	cmsglen = 0;

	if (sockets[s].pkt_info) {
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
	struct sockaddr_in sa;
	socklen_t addrlen = sizeof (sa);

	return recvfrom(sockfd, buf, len, flags, (struct sockaddr *)&sa, &addrlen);
}

int timer_create(clockid_t which_clock, struct sigevent *timer_event_spec, timer_t *created_timer_id) {
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
	timers[t].clock_id = which_clock;
	*created_timer_id = get_timerid(t);

	return 0;
}

int timer_delete(timer_t timerid) {
	int t = get_timer_from_id(timerid);

	if (t < 0) {
		errno = EINVAL;
		return -1;
	}

	timers[t].used = 0;

	return 0;
}

int timer_settime(timer_t timerid, int flags, const struct itimerspec *value, struct itimerspec *ovalue) {
	int t = get_timer_from_id(timerid);

	if (t < 0) {
		errno = EINVAL;
		return -1;
	}

	assert(value && ovalue == NULL &&
	       (flags == 0 || (flags == TIMER_ABSTIME && timers[t].clock_id == CLOCK_MONOTONIC)));

	if (value->it_value.tv_sec || value->it_value.tv_nsec) {
		timers[t].armed = 1;
		timers[t].timeout = timespec_to_time(&value->it_value, 0);
		if (!(flags & TIMER_ABSTIME))
			timers[t].timeout += get_monotonic_time();
		timers[t].interval = timespec_to_time(&value->it_interval, 0);
	} else {
		timers[t].armed = 0;
	}

	return 0;
}

int timer_gettime(timer_t timerid, struct itimerspec *value) {
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

	assert((clockid == CLOCK_REALTIME || clockid == CLOCK_MONOTONIC) && !flags);

	t = get_free_timer();
	if (t < 0) {
		assert(0);
		errno = ENOMEM;
		return -1;
	}

	timers[t].used = 1;
	timers[t].armed = 0;
	timers[t].type = TIMER_TYPE_FD;
	timers[t].clock_id = clockid;

	return get_timerfd(t);
}

int timerfd_settime(int fd, int flags, const struct itimerspec *new_value, struct itimerspec *old_value) {
	if (flags == TFD_TIMER_ABSTIME)
		flags = TIMER_ABSTIME;
	else
		assert(!flags);

	return timer_settime(get_timerid(get_timer_from_fd(fd)), flags, new_value, old_value);
}

int timerfd_gettime(int fd, struct itimerspec *curr_value) {
	return timer_gettime(get_timerid(get_timer_from_fd(fd)), curr_value);
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
		default:
			assert(0);
	}
	va_end(ap);

	return r;
}
#endif

ssize_t getrandom(void *buf, size_t length, unsigned int flags) {
	errno = ENOTSUP;
	return -1;
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
