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
#include <stdlib.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdarg.h>
#include <signal.h>
#include <ifaddrs.h>
#include <linux/ptp_clock.h>
#include <linux/ethtool.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <sys/timerfd.h>

#include "protocol.h"

#define NTP_PORT 123
#define PTP_EVENT_PORT 319
#define PTP_GENERAL_PORT 320
#define BASE_ADDR 0xc0a87b01 /* 192.168.123.1 */
#define BROADCAST_ADDR (BASE_ADDR | 0xff)
#define NETMASK 0xffffff00
#define PTP_PRIMARY_MCAST_ADDR 0xe0000181 /* 224.0.1.129 */
#define PTP_PDELAY_MCAST_ADDR 0xe000006b /* 224.0.0.107 */

#define REFCLK_FD 1000
#define REFCLK_ID ((~(clockid_t)REFCLK_FD << 3) | 3)
#define REFCLK_PHC_INDEX 0
#define SYSCLK_FD 1001
#define SYSCLK_CLOCKID ((~(clockid_t)SYSCLK_FD << 3) | 3)
#define SYSCLK_PHC_INDEX 1

#define SCALED_PPM_PER_TICK 6553600
#define BASE_TICK 10000

#define MIN_SOCKET_FD 100
#define MAX_SOCKET_FD 199
#define MAX_TIMERS 20
#define BASE_TIMER_ID 0xC1230123
#define BASE_TIMER_FD 200

static FILE *(*_fopen)(const char *path, const char *mode);
static int (*_open)(const char *pathname, int flags);
static int (*_close)(int fd);
static int (*_socket)(int domain, int type, int protocol);
static int (*_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
static ssize_t (*_recvmsg)(int sockfd, struct msghdr *msg, int flags);
static int (*_usleep)(useconds_t usec);

static unsigned int node;
static int initialized = 0;
static int clknetsim_fd;
static int precision_hack = 1;

static int ntp_eth_fd = 0;
static int ntp_any_fd = 0;
static int ntp_broadcast_fd = 0;
static int ptp_event_fd = 0;
static int ptp_general_fd = 0;
static int last_socket_fd = MIN_SOCKET_FD - 1;

static double local_time = 0.0;
static double local_mono_time = 0.0;
static int local_time_valid = 0;
static double network_time = 0.0;

static time_t system_time_offset = 1262304000; /* 2010-01-01 0:00 UTC */

#define TIMER_TYPE_SIGNAL 1
#define TIMER_TYPE_FD 2

struct timer {
	int used;
	int armed;
	int type;
	double timeout;
	double interval;
};

static struct timer timers[MAX_TIMERS];

static timer_t itimer_real_id;

#define SHMKEY 0x4e545030

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
} shm_time;

static int refclock_shm_enabled = 0;
static double refclock_time = 0.0;
static struct Reply_getrefoffsets refclock_offsets;
static int refclock_offsets_used = REPLY_GETREFOFFSETS_SIZE;

static void make_request(int request_id, const void *request_data, int reqlen, void *reply, int replylen);

static void init(void) {
	struct Request_register req;
	struct Reply_empty rep;
	struct sockaddr_un s = {AF_UNIX, "clknetsim.sock"};
	const char *env;

	assert(!initialized);

	_fopen = (FILE *(*)(const char *path, const char *mode))dlsym(RTLD_NEXT, "fopen");
	_open = (int (*)(const char *pathname, int flags))dlsym(RTLD_NEXT, "open");
	_close = (int (*)(int fd))dlsym(RTLD_NEXT, "close");
	_socket = (int (*)(int domain, int type, int protocol))dlsym(RTLD_NEXT, "socket");
	_connect = (int (*)(int sockfd, const struct sockaddr *addr, socklen_t addrlen))dlsym(RTLD_NEXT, "connect");
	_recvmsg = (ssize_t (*)(int sockfd, struct msghdr *msg, int flags))dlsym(RTLD_NEXT, "recvmsg");
	_usleep = (int (*)(useconds_t usec))dlsym(RTLD_NEXT, "usleep");

	env = getenv("CLKNETSIM_NODE");
	if (!env) {
		fprintf(stderr, "CLKNETSIM_NODE variable not set.\n");
		exit(1);
	}
	node = atoi(env) - 1;

	env = getenv("CLKNETSIM_SOCKET");
	if (env)
		snprintf(s.sun_path, sizeof (s.sun_path), "%s", env);

	env = getenv("CLKNETSIM_START_DATE");
	if (env)
		system_time_offset = atol(env);

	clknetsim_fd = _socket(AF_UNIX, SOCK_STREAM, 0);

	assert(clknetsim_fd >= 0);

	while (_connect(clknetsim_fd, (struct sockaddr *)&s, sizeof (s)) < 0)
		_usleep(100000);

	initialized = 1;

	req.node = node;
	make_request(REQ_REGISTER, &req, sizeof (req), &rep, sizeof (rep));
}

static void make_request(int request_id, const void *request_data, int reqlen, void *reply, int replylen) {
	struct Request_header *header;
	char buf[MAX_REQ_SIZE];
	int sent, received;

	header = (struct Request_header *)buf;
	header->request = request_id;

	assert(reqlen + sizeof (struct Request_header) <= MAX_REQ_SIZE);

	if (request_data)
		memcpy(buf + sizeof (struct Request_header), request_data, reqlen);
	reqlen += sizeof (struct Request_header);

	if ((sent = send(clknetsim_fd, buf, reqlen, 0)) <= 0 ||
			(received = recv(clknetsim_fd, reply, replylen, 0)) <= 0) {
		fprintf(stderr, "clknetsim connection closed.\n");
		exit(1);
	}

	assert(sent == reqlen);
	assert(received == replylen);
}

static double gettime(void) {
	struct Reply_gettime r;

	if (!initialized)
		init();

	if (!local_time_valid) {
		make_request(REQ_GETTIME, NULL, 0, &r, sizeof (r));
		local_time = r.time;
		local_mono_time = r.mono_time;
		local_time_valid = 1;
		network_time = r.network_time;
	}

	return local_time;
}

static double getmonotime(void) {
	gettime();
	return local_mono_time;
}

static double getphctime(void) {
	gettime();
	if (refclock_offsets_used >= REPLY_GETREFOFFSETS_SIZE) {
		make_request(REQ_GETREFOFFSETS, NULL, 0, &refclock_offsets, sizeof (refclock_offsets));
		refclock_offsets_used = 0;
	}
	return network_time - refclock_offsets.offsets[refclock_offsets_used++];
}

static void settime(double time) {
	struct Request_settime req;
	struct Reply_empty rep;

	if (!initialized)
		init();

	req.time = time;
	make_request(REQ_SETTIME, &req, sizeof (req), &rep, sizeof (rep));

	local_time_valid = 0;
}

static void fill_refclock_sample(void) {
	struct Reply_getreftime r;
	double clock_time, receive_time;

	if (!refclock_shm_enabled)
		return;

	if (!initialized)
		init();

	make_request(REQ_GETREFTIME, NULL, 0, &r, sizeof (r));

	if (r.time == refclock_time || !r.valid)
		return;
	refclock_time = r.time;

	clock_time = r.time + 0.5e-6;
	receive_time = r.time + r.offset + 0.5e-6;

	shm_time.count++;
	shm_time.clockTimeStampSec = floor(clock_time);
	shm_time.clockTimeStampUSec = (clock_time - shm_time.clockTimeStampSec) * 1e6;
	shm_time.clockTimeStampNSec = (clock_time - shm_time.clockTimeStampSec) * 1e9;
	shm_time.clockTimeStampSec += system_time_offset;
	shm_time.receiveTimeStampSec = floor(receive_time);
	shm_time.receiveTimeStampUSec = (receive_time - shm_time.receiveTimeStampSec) * 1e6;
	shm_time.receiveTimeStampNSec = (receive_time - shm_time.receiveTimeStampSec) * 1e9;
	shm_time.receiveTimeStampSec += system_time_offset;
	shm_time.leap = 0;
	shm_time.valid = 1;
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
		if (timers[i].type == TIMER_TYPE_FD && !FD_ISSET(get_timerfd(i), timerfds))
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

int gettimeofday(struct timeval *tv, struct timezone *tz) {
	double time;

	time = gettime() + 0.5e-6;

	tv->tv_sec = floor(time);
	tv->tv_usec = (time - tv->tv_sec) * 1e6;
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
			time = gettime();
			break;
		case CLOCK_MONOTONIC:
			time = getmonotime();
			break;
		case REFCLK_ID:
			time = getphctime();
			break;
		default:
			assert(0);
	}

	time += 0.5e-9;
	tp->tv_sec = floor(time);
	tp->tv_nsec = (time - tp->tv_sec) * 1e9;
	
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

	time = floor(gettime());
	time += system_time_offset;
	if (t)
		*t = time;
	return time;
}

int settimeofday(const struct timeval *tv, const struct timezone *tz) {
	assert(tv);
	settime(tv->tv_sec - system_time_offset + tv->tv_usec / 1e6);
	return 0;
}

int clock_settime(clockid_t which_clock, const struct timespec *tp) {
	assert(tp && which_clock == CLOCK_REALTIME);
	settime(tp->tv_sec - system_time_offset + tp->tv_nsec * 1e-9);
	return 0;
}

int adjtimex(struct timex *buf) {
	struct Request_adjtimex req;
	struct Reply_adjtimex rep;

	if (!initialized)
		init();

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
	assert(id == CLOCK_REALTIME || id == SYSCLK_CLOCKID);

	/* allow large frequency adjustment by setting ticks */
	if (id == SYSCLK_CLOCKID) {
		int r;

		if (tx->modes & ADJ_FREQUENCY && !(tx->modes & ADJ_TICK))
			tx->tick = BASE_TICK, tx->modes |= ADJ_TICK;

		tx->tick += tx->freq / SCALED_PPM_PER_TICK;
		tx->freq = tx->freq % SCALED_PPM_PER_TICK;

		r = adjtimex(tx);

		tx->freq += (tx->tick - BASE_TICK) * SCALED_PPM_PER_TICK;
		tx->tick = BASE_TICK;

		return r;
	}

	return adjtimex(tx);
}

int adjtime(const struct timeval *delta, struct timeval *olddelta) {
	struct Request_adjtime req;
	struct Reply_adjtime rep;

	if (!initialized)
		init();

	req.tv = *delta;
	make_request(REQ_ADJTIME, &req, sizeof (req), &rep, sizeof (rep));
	if (olddelta)
		*olddelta = rep.tv;
	
	return 0;
}

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
	struct Request_select req;
	struct Reply_select rep;
	double time;
	int timer, any_fd_set;

	if (!initialized)
		init();

	timer = get_first_timer(readfds);

	if (ntp_eth_fd || ntp_any_fd || ptp_event_fd || ptp_general_fd) {
		assert(!ntp_eth_fd || FD_ISSET(ntp_eth_fd, readfds));
		assert(!ntp_any_fd || FD_ISSET(ntp_any_fd, readfds));
		assert(!ptp_event_fd || FD_ISSET(ptp_event_fd, readfds));
		assert(!ptp_general_fd || FD_ISSET(ptp_general_fd, readfds));
		any_fd_set = 1;
	} else {
		any_fd_set = 0;
	}

	assert((timeout && (timeout->tv_sec > 0 || timeout->tv_usec > 0)) ||
			timer >= 0 || any_fd_set);

	time = getmonotime();

	if (timeout)
		req.timeout = timeout->tv_sec + (timeout->tv_usec + 1) / 1e6;
	else
		req.timeout = 1e20;

	if (timer >= 0 && timers[timer].timeout <= time) {
		/* avoid unnecessary requests */
		rep.ret = REPLY_SELECT_TIMEOUT;
	} else {
		if (timer >= 0 && time + req.timeout > timers[timer].timeout)
			req.timeout = timers[timer].timeout - time;

		make_request(REQ_SELECT, &req, sizeof (req), &rep, sizeof (rep));

		local_time_valid = 0;
		time = getmonotime();

		fill_refclock_sample();

		if (time >= 0.1 || timer >= 0 || any_fd_set)
			precision_hack = 0;
	}

	if (readfds)
		FD_ZERO(readfds);

	if (rep.ret == REPLY_SELECT_TERMINATE) {
		kill(getpid(), SIGTERM);
		errno = EINTR;
		return -1;
	}

	if (rep.ret == REPLY_SELECT_TIMEOUT && timer >= 0 && time >= timers[timer].timeout) {
		rearm_timer(timer);
		switch (timers[timer].type) {
			case TIMER_TYPE_SIGNAL:
				kill(getpid(), SIGALRM);
				errno = EINTR;
				return -1;
			case TIMER_TYPE_FD:
				FD_SET(get_timerfd(timer), readfds);
				return 1;
			default:
				assert(0);
		}
	}

	if (rep.ret == REPLY_SELECT_NORMAL || (rep.ret == REPLY_SELECT_BROADCAST && !ntp_broadcast_fd)) {
		switch (rep.port) {
			case NTP_PORT:
				assert(ntp_eth_fd || ntp_any_fd);
				FD_SET(ntp_eth_fd ? ntp_eth_fd : ntp_any_fd, readfds);
				break;
			case PTP_EVENT_PORT:
				assert(ptp_event_fd);
				FD_SET(ptp_event_fd, readfds);
				break;
			case PTP_GENERAL_PORT:
				assert(ptp_general_fd);
				FD_SET(ptp_general_fd, readfds);
				break;
		}
		return 1;
	}

	if (rep.ret == REPLY_SELECT_BROADCAST && ntp_broadcast_fd) {
		assert(rep.port == NTP_PORT);
		FD_SET(ntp_broadcast_fd, readfds);
		return 1;
	}

	assert(rep.ret == REPLY_SELECT_TIMEOUT);
	return 0;
}

#if 1
int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
	struct timeval tv, *ptv = NULL;
	int r, maxfd = 0;
	nfds_t i;
	fd_set rfds;

	/* ptp4l waiting for tx SO_TIMESTAMPING */
	if (nfds == 1 && ptp_event_fd && fds[0].fd == ptp_event_fd && !fds[0].events) {
		fds[0].revents = POLLERR;
		return 1;
	}

	FD_ZERO(&rfds);

	for (i = 0; i < nfds; i++)
		if (fds[i].events & POLLIN) {
			FD_SET(fds[i].fd, &rfds);
			if (maxfd < fds[i].fd)
				maxfd = fds[i].fd;
		}

	if (timeout >= 0) {
		tv.tv_sec = timeout / 1000;
		tv.tv_usec = (timeout % 1000) * 1000;
		ptv = &tv;
	}

	r = select(maxfd, &rfds, NULL, NULL, ptv);

	for (i = 0; i < nfds; i++)
		fds[i].revents = r > 0 && FD_ISSET(fds[i].fd, &rfds) ? POLLIN : 0;

	return r;
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
	assert(r == 0);

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

FILE *fopen(const char *path, const char *mode) {
	if (!strcmp(path, "/proc/net/if_inet6")) {
		errno = ENOENT;
		return NULL;
	}

	return _fopen(path, mode);
}

int open(const char *pathname, int flags) {
	assert(REFCLK_PHC_INDEX == 0 || SYSCLK_PHC_INDEX == 1);
	if (!strcmp(pathname, "/dev/ptp0"))
		return REFCLK_FD;
	else if (!strcmp(pathname, "/dev/ptp1"))
		return SYSCLK_FD;

	return _open(pathname, flags);
}

int close(int fd) {
	int t;

	if (fd == REFCLK_FD || fd == SYSCLK_FD) {
		return 0;
	} else if (fd == ntp_any_fd) {
		ntp_any_fd = 0;
		return 0;
	} else if (fd == ntp_eth_fd) {
		ntp_eth_fd = 0;
		return 0;
	} else if (fd == ntp_broadcast_fd) {
		ntp_broadcast_fd = 0;
		return 0;
	} else if (fd == ptp_event_fd) {
		ptp_event_fd = 0;
		return 0;
	} else if (fd == ptp_general_fd) {
		ptp_general_fd = 0;
		return 0;
	} else if ((t = get_timer_from_fd(fd)) >= 0) {
		return timer_delete(get_timerid(t));
	} else if (fd >= MIN_SOCKET_FD && fd <= MAX_SOCKET_FD)
		return 0;

	return _close(fd);
}

int socket(int domain, int type, int protocol) {
	if (domain == AF_INET && SOCK_DGRAM) {
		last_socket_fd++;
		if (last_socket_fd > MAX_SOCKET_FD)
			last_socket_fd = MIN_SOCKET_FD;
		return last_socket_fd;
	}
	errno = EINVAL;
	return -1;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	if (addr->sa_family == AF_INET && ntohs(((const struct sockaddr_in *)addr)->sin_port) == NTP_PORT)
		return 0;
	errno = EINVAL;
	return -1;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	struct sockaddr_in *in;
	if (addr->sa_family != AF_INET) {
		errno = EINVAL;
		return -1;
	}
	       
	in = (struct sockaddr_in *)addr;

	switch (ntohs(in->sin_port)) {
		case 0:
		case NTP_PORT:
			if (ntohl(in->sin_addr.s_addr) == INADDR_ANY)
				ntp_any_fd = sockfd;
			else if (ntohl(in->sin_addr.s_addr) == BASE_ADDR + node)
				ntp_eth_fd = sockfd;
			else if (ntohl(in->sin_addr.s_addr) == BROADCAST_ADDR) 
				ntp_broadcast_fd = sockfd;
			else if (ntohl(in->sin_addr.s_addr) == INADDR_LOOPBACK)
				return 0;
			else
				assert(0);
			break;
		case PTP_EVENT_PORT:
			assert(ntohl(in->sin_addr.s_addr) == INADDR_ANY);
			ptp_event_fd = sockfd;
			break;
		case PTP_GENERAL_PORT:
			assert(ntohl(in->sin_addr.s_addr) == INADDR_ANY);
			ptp_general_fd = sockfd;
			break;
	}

	return 0;
}

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	struct sockaddr_in *in;
	in = (struct sockaddr_in *)addr;
	assert(*addrlen >= sizeof (*in));
	*addrlen = sizeof (*in);
	in->sin_family = AF_INET;
	in->sin_addr.s_addr = htonl(BASE_ADDR + node);
	return 0;
}

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
	return 0;
	errno = EINVAL;
	return -1;
}

int fcntl(int fd, int cmd, ...) {
	return 0;
}

int ioctl(int fd, unsigned long request, ...) {
	va_list ap;
	struct ifconf *conf;
	struct ifreq *req;
	int ret = 0;

	va_start(ap, request);

	if (request == SIOCGIFCONF) {
		conf = va_arg(ap, struct ifconf *);
		conf->ifc_len = sizeof (struct ifreq) * 2;
		sprintf(conf->ifc_req[0].ifr_name, "lo");
		sprintf(conf->ifc_req[1].ifr_name, "eth0");
		((struct sockaddr_in*)&conf->ifc_req[0].ifr_addr)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		((struct sockaddr_in*)&conf->ifc_req[1].ifr_addr)->sin_addr.s_addr = htonl(BASE_ADDR + node);
		conf->ifc_req[0].ifr_addr.sa_family = AF_INET;
		conf->ifc_req[1].ifr_addr.sa_family = AF_INET;
	} else if (request == SIOCGIFINDEX) {
		req = va_arg(ap, struct ifreq *);
		if (!strcmp(req->ifr_name, "lo"))
			req->ifr_ifindex = 0;
		else if (!strcmp(req->ifr_name, "eth0"))
			req->ifr_ifindex = 1;
		else
			ret = -1, errno = EINVAL;
	} else if (request == SIOCGIFFLAGS) {
		req = va_arg(ap, struct ifreq *);
		if (!strcmp(req->ifr_name, "lo"))
			req->ifr_flags = IFF_UP | IFF_LOOPBACK;
		else if (!strcmp(req->ifr_name, "eth0"))
			req->ifr_flags = IFF_UP | IFF_BROADCAST;
		else
			ret = -1, errno = EINVAL;
	} else if (request == SIOCGIFBRDADDR) {
		req = va_arg(ap, struct ifreq *);
		if (!strcmp(req->ifr_name, "eth0"))
			((struct sockaddr_in*)&req->ifr_broadaddr)->sin_addr.s_addr = htonl(BROADCAST_ADDR);
		else
			ret = -1, errno = EINVAL;
		req->ifr_broadaddr.sa_family = AF_INET;
	} else if (request == SIOCGIFNETMASK) {
		req = va_arg(ap, struct ifreq *);
		if (!strcmp(req->ifr_name, "lo"))
			((struct sockaddr_in*)&req->ifr_netmask)->sin_addr.s_addr = htonl(0xff000000);
		else if (!strcmp(req->ifr_name, "eth0"))
			((struct sockaddr_in*)&req->ifr_netmask)->sin_addr.s_addr = htonl(NETMASK);
		else
			ret = -1, errno = EINVAL;
		req->ifr_netmask.sa_family = AF_INET;
	} else if (request == SIOCGIFHWADDR) {
		char mac[IFHWADDRLEN] = {0x12, 0x23, 0x45, 0x67, 0x78, node + 1};
		req = va_arg(ap, struct ifreq *);
		if (!strcmp(req->ifr_name, "lo"))
			memset((&req->ifr_hwaddr)->sa_data, 0, sizeof (mac));
		else if (!strcmp(req->ifr_name, "eth0"))
			memcpy((&req->ifr_hwaddr)->sa_data, mac, sizeof (mac));
		else
			ret = -1, errno = EINVAL;
		req->ifr_netmask.sa_family = AF_UNSPEC;
#ifdef ETHTOOL_GET_TS_INFO
	} else if (request == SIOCETHTOOL) {
		struct ethtool_ts_info *info;
		req = va_arg(ap, struct ifreq *);
		info = (struct ethtool_ts_info *)req->ifr_data;
		memset(info, 0, sizeof (*info));
		if (!strcmp(req->ifr_name, "eth0")) {
			info->phc_index = SYSCLK_PHC_INDEX;
			info->so_timestamping = SOF_TIMESTAMPING_SOFTWARE |
				SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_RX_SOFTWARE |
				SOF_TIMESTAMPING_RAW_HARDWARE |
				SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_RX_HARDWARE;
			info->tx_types = HWTSTAMP_TX_ON;
			info->rx_filters = HWTSTAMP_FILTER_NONE | HWTSTAMP_FILTER_ALL;
		} else
			ret = -1, errno = EINVAL;
#endif
#ifdef PTP_CLOCK_GETCAPS
	} else if (request == PTP_CLOCK_GETCAPS && (fd == REFCLK_FD || fd == SYSCLK_FD)) {
		struct ptp_clock_caps *caps = va_arg(ap, struct ptp_clock_caps *);
		memset(caps, 0, sizeof (*caps));
		caps->max_adj = 100000000;
#endif
#ifdef SIOCSHWTSTAMP
	} else if (request == SIOCSHWTSTAMP && fd == ptp_event_fd) {
#endif
	} else {
		ret = -1;
		errno = EINVAL;
	}

	va_end(ap);
	return ret;
}

int getifaddrs(struct ifaddrs **ifap) {
	static struct sockaddr_in addrs[5];
	static struct ifaddrs ifaddrs[2];
	uint32_t sin_addrs[5] = {INADDR_LOOPBACK, 0xff000000, BASE_ADDR + node, NETMASK, BROADCAST_ADDR};
	int i;
       
	ifaddrs[0] = (struct ifaddrs){
		.ifa_next = &ifaddrs[1],
		.ifa_name = "lo",
		.ifa_flags = IFF_UP | IFF_LOOPBACK,
		.ifa_addr = (struct sockaddr *)&addrs[0],
		.ifa_netmask = (struct sockaddr *)&addrs[1]
	};

	ifaddrs[1] = (struct ifaddrs){
		.ifa_name = "eth0",
		.ifa_flags = IFF_UP | IFF_BROADCAST,
		.ifa_addr = (struct sockaddr *)&addrs[2],
		.ifa_netmask = (struct sockaddr *)&addrs[3],
		.ifa_broadaddr = (struct sockaddr *)&addrs[4]
	};

	for (i = 0; i < 5; i++)
		addrs[i] = (struct sockaddr_in){
			.sin_addr.s_addr = htonl(sin_addrs[i]),
			.sin_family = AF_INET
		};

	*ifap = ifaddrs;
	return 0;
}

void freeifaddrs(struct ifaddrs *ifa) {
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
	struct Request_send req;
	struct Reply_empty rep;

	struct sockaddr_in *sa;

	if (sockfd != ntp_eth_fd && sockfd != ntp_any_fd &&
			sockfd != ptp_event_fd && sockfd != ptp_general_fd) {
		printf("sendmsg inval sockfd\n");
		errno = EINVAL;
		return -1;
	}

	if (!initialized)
		init();

	sa = msg->msg_name;

	assert(sa && msg->msg_namelen >= sizeof (struct sockaddr_in));
	assert(sa->sin_family == AF_INET);
	assert(msg->msg_iovlen == 1);
	assert(msg->msg_iov[0].iov_len <= MAX_PACKET_SIZE);

	if (sa->sin_addr.s_addr == htonl(BROADCAST_ADDR) ||
			sa->sin_addr.s_addr == htonl(PTP_PRIMARY_MCAST_ADDR) ||
			sa->sin_addr.s_addr == htonl(PTP_PDELAY_MCAST_ADDR))
		req.to = -1; /* broadcast */
	else
		req.to = ntohl(sa->sin_addr.s_addr) - BASE_ADDR;

	assert(req.to == -1 || req.to < BROADCAST_ADDR - BASE_ADDR);

	req.port = ntohs(sa->sin_port);

	assert((req.port == NTP_PORT && (sockfd == ntp_eth_fd || sockfd == ntp_any_fd)) ||
			(req.port == PTP_EVENT_PORT && sockfd == ptp_event_fd) ||
			(req.port == PTP_GENERAL_PORT && sockfd == ptp_general_fd));

	req.len = msg->msg_iov[0].iov_len;
	memcpy(req.data, msg->msg_iov[0].iov_base, req.len);

	make_request(REQ_SEND, &req, sizeof (req), &rep, sizeof (rep));

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

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
	struct Reply_recv rep;
	struct sockaddr_in *sa;

	if (sockfd != ntp_eth_fd && sockfd != ntp_any_fd && sockfd != ntp_broadcast_fd &&
			sockfd != ptp_event_fd && sockfd != ptp_general_fd)
		return _recvmsg(sockfd, msg, flags);

	if (!initialized)
		init();

	if (sockfd == ptp_event_fd && flags == MSG_ERRQUEUE) {
		/* dummy message for tx time stamp */
		rep.from = node;
		rep.port = PTP_EVENT_PORT;
		rep.len = 1;
		rep.data[0] = 0;
	} else
		make_request(REQ_RECV, NULL, 0, &rep, sizeof (rep));

	if (rep.len == 0) {
		errno = EWOULDBLOCK;
		return -1;
	}

	assert((rep.port == NTP_PORT && (sockfd == ntp_eth_fd || sockfd == ntp_any_fd)) ||
			(rep.port == PTP_EVENT_PORT && sockfd == ptp_event_fd) ||
			(rep.port == PTP_GENERAL_PORT && sockfd == ptp_general_fd));

	if (msg->msg_name) {
		assert(msg->msg_namelen >= sizeof (struct sockaddr_in));

		sa = msg->msg_name;
		sa->sin_family = AF_INET;
		sa->sin_port = htons(rep.port);
		sa->sin_addr.s_addr = htonl(BASE_ADDR + rep.from);
		msg->msg_namelen = sizeof (struct sockaddr_in);
	}

	assert(msg->msg_iovlen == 1);
	assert(msg->msg_iov[0].iov_len >= rep.len);
	memcpy(msg->msg_iov[0].iov_base, rep.data, rep.len);

	if (sockfd == ptp_event_fd) {
		struct timespec ts;
		struct cmsghdr *cmsg;
		int len = CMSG_SPACE(3 * sizeof (struct timespec));

		clock_gettime(CLOCK_REALTIME, &ts);

		assert(msg->msg_control && msg->msg_controllen >= len);

		cmsg = CMSG_FIRSTHDR(msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SO_TIMESTAMPING;
		cmsg->cmsg_len = len;

		/* copy as sw and hw time stamp */
		memcpy((struct timespec *)CMSG_DATA(cmsg), &ts, sizeof (ts));
		memcpy((struct timespec *)CMSG_DATA(cmsg) + 2, &ts, sizeof (ts));

		msg->msg_controllen = len;
	} else
		msg->msg_controllen = 0;

	return rep.len;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
	ssize_t ret;
	struct msghdr msg;
	struct iovec iov;

	iov.iov_base = (void *)buf;
	iov.iov_len = len;

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
	timers[t].type = TIMER_TYPE_SIGNAL;
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

	assert(flags == 0 && value && ovalue == NULL);

	if (t < 0) {
		errno = EINVAL;
		return -1;
	}

	if (value->it_value.tv_sec || value->it_value.tv_nsec) {
		timers[t].armed = 1;
		timers[t].timeout = getmonotime() + value->it_value.tv_sec + value->it_value.tv_nsec * 1e-9;
		timers[t].interval = value->it_interval.tv_sec + value->it_interval.tv_nsec * 1e-9;
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
		timeout = timers[t].timeout - getmonotime();
		value->it_value.tv_sec = timeout;
		value->it_value.tv_nsec = (timeout - value->it_value.tv_sec) * 1e9;
	} else {
		value->it_value.tv_sec = 0;
		value->it_value.tv_nsec = 0;
	}
	value->it_interval.tv_sec = timers[t].interval;
	value->it_interval.tv_nsec = (timers[t].interval - value->it_interval.tv_sec) * 1e9;

	return 0;
}

#if 1
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
	int r;

	assert(which == ITIMER_REAL);

	r = timer_gettime(itimer_real_id, &timerspec);
	curr_value->it_interval.tv_sec = timerspec.it_interval.tv_sec;
	curr_value->it_interval.tv_usec = timerspec.it_interval.tv_nsec / 1000;
	curr_value->it_value.tv_sec = timerspec.it_value.tv_sec;
	curr_value->it_value.tv_usec = timerspec.it_value.tv_nsec / 1000;

	return r; 
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
	timers[t].type = TIMER_TYPE_FD;

	return get_timerfd(t);
}

int timerfd_settime(int fd, int flags, const struct itimerspec *new_value, struct itimerspec *old_value) {
	assert(!flags);

	return timer_settime(get_timerid(get_timer_from_fd(fd)), 0, new_value, old_value);
}

int timerfd_gettime(int fd, struct itimerspec *curr_value) {
	return timer_gettime(get_timerid(get_timer_from_fd(fd)), curr_value);
}

int shmget(key_t key, size_t size, int shmflg) {
	if (key == SHMKEY)
		return SHMKEY;
	return -1;
}

void *shmat(int shmid, const void *shmaddr, int shmflg) {
	assert(shmid == SHMKEY);

	refclock_shm_enabled = 1;
	memset(&shm_time, 0, sizeof (shm_time));
	shm_time.mode = 1;
	shm_time.precision = -20;

	return &shm_time;
}

int shmdt(const void *shmaddr) {
	assert(shmaddr == &shm_time);
	refclock_shm_enabled = 0;
	return 0;
}

uid_t getuid(void) {
	return 0;
}

int uname(struct utsname *buf) {
	memset(buf, 0, sizeof (*buf));
	sprintf(buf->sysname, "Linux (clknetsim)");
	sprintf(buf->release, "2.6.39");
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
