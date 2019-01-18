/*
 * Copyright (C) 2015  Miroslav Lichvar <mlichvar@redhat.com>
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

/* This is a minimal replacement for the clknetsim server to allow fuzz
   testing. There is no clock control or networking. When the time reaches
   fuzz_start, a packet read from stdin is forwarded to the fuzz_port port of
   the client, and the client is terminated. Packets sent by the client from
   the port are written to stdout. */

enum {
	FUZZ_MODE_DISABLED = 0,
	FUZZ_MODE_ONESHOT = 1,
	FUZZ_MODE_BURST = 2,
	FUZZ_MODE_REPLY = 3,
	FUZZ_MODE_NONE = 4,
};

#define FUZZ_FLAG_TIMEOUT 1024

#define MAX_FUZZ_PORTS 16

static int fuzz_mode;
static int fuzz_ports[MAX_FUZZ_PORTS];
static int fuzz_port_index, fuzz_ports_n;
static int fuzz_timeout;
static double fuzz_start;

static int fuzz_init(void) {
	const char *env;

	env = getenv("CLKNETSIM_FUZZ_MODE");
	if (!env)
		return 0;

	fuzz_mode = atoi(env);

	if (fuzz_mode & FUZZ_FLAG_TIMEOUT) {
		fuzz_timeout = 1;
		fuzz_mode &= ~FUZZ_FLAG_TIMEOUT;
	}

	if (fuzz_mode == FUZZ_MODE_DISABLED)
		return 0;

	if (fuzz_mode < FUZZ_MODE_ONESHOT || fuzz_mode > FUZZ_MODE_NONE) {
		fprintf(stderr, "clknetsim: unknown fuzz mode.\n");
		exit(1);
	}

	env = getenv("CLKNETSIM_FUZZ_PORT");

	for (fuzz_ports_n = 0; env && fuzz_ports_n < MAX_FUZZ_PORTS; fuzz_ports_n++) {
		fuzz_ports[fuzz_ports_n] = atoi(env);
		if (!fuzz_ports[fuzz_ports_n])
			break;
		env = strchr(env, ',');
		if (env)
			env++;
	}

	if (!fuzz_ports_n) {
		fprintf(stderr, "clknetsim: CLKNETSIM_FUZZ_PORT variable not set or invalid.\n");
		exit(1);
	}
	fuzz_port_index = 0;

	env = getenv("CLKNETSIM_FUZZ_START");
	fuzz_start = env ? atof(env) : 0.1;

	return 1;
}

static int fuzz_is_fuzz_port(int port) {
	int i;

	for (i = 0; i < fuzz_ports_n; i++)
		if (fuzz_ports[i] == port)
			return 1;
	return 0;
}

static int fuzz_get_fuzz_port(void) {
	return fuzz_ports[fuzz_port_index];
}

static void fuzz_switch_fuzz_port(void) {
	fuzz_port_index = (fuzz_port_index + 1) % fuzz_ports_n;
}

static int fuzz_read_packet(char *data, int maxlen, int *rlen) {
	int len;
	uint16_t slen;

	if (fuzz_mode > FUZZ_MODE_ONESHOT) {
		if (fread(&slen, 1, sizeof (slen), stdin) != sizeof (slen))
			return 0;
		len = ntohs(slen);
		if (len > maxlen)
			len = maxlen;
	} else {
		len = maxlen;
	}

	*rlen = fread(data, 1, len, stdin);

	return !len || rlen;
}

static void fuzz_write_packet(const char *data, int len) {
	uint16_t slen;

	if (fuzz_mode > FUZZ_MODE_ONESHOT) {
		slen = htons(len);
		fwrite(&slen, 1, sizeof (slen), stdout);
	}

	fwrite(data, 1, len, stdout);
}

static void fuzz_process_reply(int request_id, const union Request_data *request, union Reply_data *reply, int replylen) {
	static double network_time = 0.0;
	static int received = 0;
	static int sent = 0;
	static int dst_port = 0;
	static int packet_len = 0;
	static int valid_packet = 0;
	static char packet[MAX_PACKET_SIZE];

	if (reply)
		memset(reply, 0, replylen);

	switch (request_id) {
		case REQ_GETTIME:
			reply->gettime.real_time = network_time;
			reply->gettime.monotonic_time = network_time;
			reply->gettime.network_time = network_time;
			break;
		case REQ_SELECT:
			if (fuzz_mode == FUZZ_MODE_NONE) {
				reply->select.ret = REPLY_SELECT_TIMEOUT;
				return;
			}

			if (!valid_packet && (!received || fuzz_mode != FUZZ_MODE_ONESHOT))
				valid_packet = fuzz_read_packet(packet, sizeof (packet), &packet_len);

			if (!valid_packet) {
				reply->select.ret = REPLY_SELECT_TERMINATE;
			} else if (!packet_len && fuzz_timeout) {
				network_time += request->select.timeout;
				reply->select.ret = REPLY_SELECT_TIMEOUT;
				valid_packet = 0;
			} else {
				if (fuzz_mode == FUZZ_MODE_REPLY) {
					if (sent > received) {
						reply->select.ret = REPLY_SELECT_NORMAL;
					} else {
						network_time += request->select.timeout;
						reply->select.ret = REPLY_SELECT_TIMEOUT;
					}
				} else {
					if (network_time < fuzz_start && !sent) {
						network_time += request->select.timeout;
						if (network_time >= fuzz_start) {
							network_time = fuzz_start;
							reply->select.ret = REPLY_SELECT_NORMAL;
						} else {
							reply->select.ret = REPLY_SELECT_TIMEOUT;
						}
					} else {
						reply->select.ret = REPLY_SELECT_NORMAL;
					}
				}
			}

			reply->select.subnet = 0;
			reply->select.dst_port = dst_port ? dst_port : fuzz_get_fuzz_port();
			reply->select.time.real_time = network_time;
			reply->select.time.monotonic_time = network_time;
			reply->select.time.network_time = network_time;
			break;
		case REQ_SEND:
			if (request->send.to != 1)
				break;

			if (fuzz_mode == FUZZ_MODE_REPLY) {
				if (!fuzz_is_fuzz_port(request->send.dst_port))
					break;
				dst_port = request->send.src_port;
			} else if (!fuzz_is_fuzz_port(request->send.src_port))
				break;

			fuzz_write_packet(request->send.data, request->send.len);
			sent++;
			break;
		case REQ_RECV:
			network_time += 1e-1;
			reply->recv.subnet = 0;
			reply->recv.from = valid_packet ? 1 : -1;
			reply->recv.src_port = fuzz_get_fuzz_port();
			reply->recv.dst_port = dst_port ? dst_port : fuzz_get_fuzz_port();
			memcpy(reply->recv.data, packet, packet_len);
			reply->recv.len = packet_len;
			received++;
			valid_packet = 0;
			packet_len = 0;
			fuzz_switch_fuzz_port();
			break;
		case REQ_SETTIME:
			network_time = request->settime.time;
			break;
		case REQ_ADJTIME:
		case REQ_GETREFSAMPLE:
		case REQ_GETREFOFFSETS:
		case REQ_DEREGISTER:
			break;
		case REQ_ADJTIMEX:
			reply->adjtimex.timex.tick = 10000;
			break;
		case REQ_REGISTER:
		default:
			assert(0);
	}
}
