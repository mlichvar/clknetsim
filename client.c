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

#include "protocol.h"

#define NTP_PORT 123
#define BASE_ADDR 0xc0a87b01 /* 192.168.123.1 */
#define BROADCAST_ADDR (BASE_ADDR | 0xff)
#define NETMASK 0xffffff00
#define SYSTEM_TIME_OFFSET 946684800 /* 0:00 01 Jan 2000 UTC */

static int (*_socket)(int domain, int type, int protocol);
static int (*_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

static unsigned int node;
static int initialized = 0;
static int sockfd;
static int select_called = 0;

static int ntp_fd = 0;
static int ntp_broadcast_fd = 0;
static int next_fd = 100;

static double local_time = 0.0;
static int local_time_valid = 0;

static timer_t timer;
static int timer_enabled = 0;
static double timer_timeout = 0.0;
static double timer_interval = 0.0;

static void make_request(int request_id, const void *request_data, int reqlen, void *reply, int replylen);

static void init() {
	struct Request_register req;
	struct Reply_empty rep;
	struct sockaddr_un s = {AF_UNIX, "clknetsim.sock"};
	const char *env;

	assert(!initialized);

	_socket = (int (*)(int domain, int type, int protocol))dlsym(RTLD_NEXT, "socket");
	_connect = (int (*)(int sockfd, const struct sockaddr *addr, socklen_t addrlen))dlsym(RTLD_NEXT, "connect");

	env = getenv("CLKNETSIM_NODE");
	if (!env) {
		fprintf(stderr, "CLKNETSIM_NODE variable not set.\n");
		exit(1);
	}
	node = atoi(env) - 1;

	env = getenv("CLKNETSIM_SOCKET");
	if (env)
		snprintf(s.sun_path, sizeof (s.sun_path), "%s", env);

	sockfd = _socket(AF_UNIX, SOCK_STREAM, 0);

	assert(sockfd >= 0);

	if (_connect(sockfd, (struct sockaddr *)&s, sizeof (s))) {
		fprintf(stderr, "Can't connect to clknetsim server.\n");
		exit(1);
	}

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

	sent = send(sockfd, buf, reqlen, 0);
	assert(sent == reqlen);

	received = recv(sockfd, reply, replylen, 0);
	if (received <= 0) {
		fprintf(stderr, "clknetsim connection closed.\n");
		exit(0);
	}
	assert(received == replylen);
}

static double gettime() {
	struct Reply_gettime r;

	if (!initialized)
		init();

	if (!local_time_valid) {
		make_request(REQ_GETTIME, NULL, 0, &r, sizeof (r));
		local_time = r.time;
		local_time_valid = 1;
	}

	return local_time;
}

static void settime(double time) {
	struct Request_settime req;
	struct Reply_empty rep;

	if (!initialized)
		init();

	req.time = time;
	make_request(REQ_SETTIME, &req, sizeof (req), &rep, sizeof (rep));

	local_time_valid = 0;
	if (timer_enabled)
		timer_timeout += gettime() - time;
}

int gettimeofday(struct timeval *tv, struct timezone *tz) {
	double time;

	time = gettime() + 0.5e-6;

	tv->tv_sec = floor(time);
	tv->tv_usec = (time - tv->tv_sec) * 1e6;
	tv->tv_sec += SYSTEM_TIME_OFFSET;

	/* chrony calibration routine hack */
	if (!select_called)
		tv->tv_usec += random() % 2;

	return 0;
}

int clock_gettime(clockid_t which_clock, struct timespec *tp) {
	double time;

	assert(which_clock == CLOCK_REALTIME);

	time = gettime() + 0.5e-9;

	tp->tv_sec = floor(time);
	tp->tv_nsec = (time - tp->tv_sec) * 1e9;
	tp->tv_sec += SYSTEM_TIME_OFFSET;

	/* ntpd calibration routine hack */
	if (!select_called)
		tp->tv_nsec += (random() % 2) * 101;

	return 0;
}

time_t time(time_t *t) {
	time_t time;

	time = floor(gettime());
	time += SYSTEM_TIME_OFFSET;
	if (t)
		*t = time;
	return time;
}

int settimeofday(const struct timeval *tv, const struct timezone *tz) {
	assert(tv);
	settime(tv->tv_sec - SYSTEM_TIME_OFFSET + tv->tv_usec / 1e6);
	return 0;
}

int clock_settime(clockid_t which_clock, const struct timespec *tp) {
	assert(tp && which_clock == CLOCK_REALTIME);
	settime(tp->tv_sec - SYSTEM_TIME_OFFSET + tp->tv_nsec * 1e-9);
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

	if (!initialized)
		init();

	assert(ntp_fd > 0);
	assert(FD_ISSET(ntp_fd, readfds));

	select_called = 1;
	time = gettime();

	if (timeout)
		req.timeout = timeout->tv_sec + (timeout->tv_usec + 1) / 1e6;
	else
		req.timeout = -1;

	if (timer_enabled && (req.timeout <= 0.0 || time + req.timeout > timer_timeout))
		req.timeout = timer_timeout - time;

	make_request(REQ_SELECT, &req, sizeof (req), &rep, sizeof (rep));

	local_time_valid = 0;
	time = gettime();

	FD_ZERO(readfds);

	if (timer_enabled && time >= timer_timeout) {
		timer_timeout += timer_interval;
		kill(getpid(), SIGALRM);
		errno = EINTR;
		return -1;
	}

	if (rep.ret == REPLY_SELECT_NORMAL || (rep.ret == REPLY_SELECT_BROADCAST && !ntp_broadcast_fd)) {
		FD_SET(ntp_fd, readfds);
		return 1;
	}

	if (rep.ret == REPLY_SELECT_BROADCAST && ntp_broadcast_fd) {
		FD_SET(ntp_broadcast_fd, readfds);
		return 1;
	}

	assert(rep.ret == REPLY_SELECT_TIMEOUT);
	return 0;
}

#if 0
int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
	struct timeval tv;
	int r, maxfd = 0;
	nfds_t i;
	fd_set rfds;

	FD_ZERO(&rfds);

	for (i = 0; i < nfds; i++)
		if (fds[i].events & POLLIN) {
			FD_SET(fds[i].fd, &rfds);
			if (maxfd < fds[i].fd)
				maxfd = fds[i].fd;
		}

	tv.tv_sec = timeout / 1000;
	tv.tv_usec = (timeout % 1000) * 1000;

	r = select(maxfd, &rfds, NULL, NULL, &tv);

	for (i = 0; i < nfds; i++)
		fds[i].revents = r > 0 && FD_ISSET(fds[i].fd, &rfds) ? POLLIN : 0;

	return r;
}
#endif

int socket(int domain, int type, int protocol) {
	if (domain == AF_INET && SOCK_DGRAM)
		return next_fd++;
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

	if (ntohs(in->sin_port) == NTP_PORT) {
		if (ntohl(in->sin_addr.s_addr) == INADDR_ANY || ntohl(in->sin_addr.s_addr) == BASE_ADDR + node)
			ntp_fd = sockfd;
		else if (ntohl(in->sin_addr.s_addr) == BROADCAST_ADDR) 
			ntp_broadcast_fd = sockfd;
		else
			assert(0);
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

int ioctl(int d, unsigned long request, ...) {
	va_list ap;
	struct ifconf *conf;
	struct ifreq *req;
	int ret = -1;

	va_start(ap, request);

	if (request == SIOCGIFCONF) {
		conf = va_arg(ap, struct ifconf *);
		conf->ifc_len = sizeof (struct ifreq);
		sprintf(conf->ifc_req->ifr_name, "eth0");
		((struct sockaddr_in*)&conf->ifc_req->ifr_addr)->sin_addr.s_addr = htonl(BASE_ADDR + node);
		conf->ifc_req->ifr_addr.sa_family = AF_INET;
		ret = 0;
	} else if (request == SIOCGIFFLAGS) {
		req = va_arg(ap, struct ifreq *);
		req->ifr_flags = IFF_UP | IFF_BROADCAST;
		ret = 0;
	} else if (request == SIOCGIFBRDADDR) {
		req = va_arg(ap, struct ifreq *);
		((struct sockaddr_in*)&req->ifr_broadaddr)->sin_addr.s_addr = htonl(BROADCAST_ADDR);
		req->ifr_broadaddr.sa_family = AF_INET;
		ret = 0;
	} else if (request == SIOCGIFNETMASK) {
		req = va_arg(ap, struct ifreq *);
		((struct sockaddr_in*)&req->ifr_netmask)->sin_addr.s_addr = htonl(NETMASK);
		req->ifr_netmask.sa_family = AF_INET;
		ret = 0;
	}

	va_end(ap);
	return ret;
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
	struct Request_send req;
	struct Reply_empty rep;

	struct sockaddr_in *sa;

	if (sockfd != ntp_fd) {
		printf("sendmsg inval sockfd\n");
		errno = EINVAL;
		return -1;
	}

	if (!initialized)
		init();

	sa = msg->msg_name;

	assert(sa && msg->msg_namelen >= sizeof (struct sockaddr_in));
	assert(sa->sin_family == AF_INET && ntohs(sa->sin_port) == NTP_PORT);
	assert(msg->msg_iovlen == 1);
	assert(msg->msg_iov[0].iov_len <= MAX_NTP_PACKETSIZE);

	if (sa->sin_addr.s_addr == htonl(BROADCAST_ADDR))
		req.to = -1; /* broadcast */
	else
		req.to = ntohl(sa->sin_addr.s_addr) - BASE_ADDR;
	req.len = msg->msg_iov[0].iov_len;
	memcpy(req.data, msg->msg_iov[0].iov_base, req.len);

	make_request(REQ_SEND, &req, sizeof (req), &rep, sizeof (rep));

	return 0;
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

	if (sockfd != ntp_fd && sockfd != ntp_broadcast_fd) {
		errno = EINVAL;
		return -1;
	}

	if (!initialized)
		init();

	sa = msg->msg_name;

	assert(sa && msg->msg_namelen >= sizeof (struct sockaddr_in));
	assert(msg->msg_iovlen == 1);

	make_request(REQ_RECV, NULL, 0, &rep, sizeof (rep));

	if (rep.len == 0) {
		errno = EWOULDBLOCK;
		return -1;
	}

	sa->sin_family = AF_INET;
	sa->sin_port = htons(NTP_PORT);
	sa->sin_addr.s_addr = htonl(BASE_ADDR + rep.from);
	msg->msg_namelen = sizeof (struct sockaddr_in);

	assert(msg->msg_iov[0].iov_len >= rep.len);
	memcpy(msg->msg_iov[0].iov_base, rep.data, rep.len);

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

int timer_create(clockid_t which_clock, struct sigevent *timer_event_spec, timer_t *created_timer_id) {
	assert(which_clock == CLOCK_REALTIME && timer_event_spec == NULL);
	timer = *created_timer_id;
	return 0;
}

int timer_settime(timer_t timerid, int flags, const struct itimerspec *value, struct itimerspec *ovalue) {
	assert(flags == 0 && value && ovalue == NULL);
	assert(timerid == timer);

	timer_enabled = 1;
	timer_timeout = gettime() + value->it_value.tv_sec + value->it_value.tv_nsec * 1e-9;
	timer_interval = value->it_interval.tv_sec + value->it_interval.tv_nsec * 1e-9;

	return 0;
}

int timer_gettime(timer_t timerid, struct itimerspec *value) {
	double timeout;

	assert(timerid == timer);
	if (!timer_enabled)
		return -1;

	timeout = timer_timeout - gettime();
	value->it_value.tv_sec = timeout;
	value->it_value.tv_nsec = (timeout - value->it_value.tv_sec) * 1e9;
	value->it_interval.tv_sec = timer_interval;
	value->it_interval.tv_nsec = (timer_interval - value->it_interval.tv_sec) * 1e9;

	return 0;
}

#if 0
int getitimer(int which, struct itimerval *curr_value) {
	assert(0);
}
int setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value) {
	assert(0);
}
#endif

uid_t getuid(void) {
	return 0;
}

int uname(struct utsname *buf) {
	memset(buf, 0, sizeof (buf));
	sprintf(buf->sysname, "Linux (clknetsim)");
	sprintf(buf->release, "2.6.33");
	return 0;
}
