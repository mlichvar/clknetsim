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

static int fuzz_port;
static double fuzz_start;

static int fuzz_init(void) {
	const char *env;

	env = getenv("CLKNETSIM_FUZZ_MODE");
	if (!env)
		return 0;

	env = getenv("CLKNETSIM_FUZZ_PORT");
	if (!env) {
		fprintf(stderr, "clknetsim: CLKNETSIM_FUZZ_PORT variable not set.\n");
		exit(1);
	}

	fuzz_port = atoi(env);

	env = getenv("CLKNETSIM_FUZZ_START");
	fuzz_start = env ? atof(env) : 0.1;

	return 1;
}

static void fuzz_process_reply(int request_id, const union Request_data *request, union Reply_data *reply, int replylen) {
	static double network_time = 0.0;
	static int received = 0;

	switch (request_id) {
		case REQ_GETTIME:
			reply->gettime.real_time = network_time;
			reply->gettime.monotonic_time = network_time;
			reply->gettime.network_time = network_time;
			break;
		case REQ_SELECT:
			if (received) {
				reply->select.ret = REPLY_SELECT_TERMINATE;
			} else if (network_time < fuzz_start) {
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

			reply->select.subnet = 0;
			reply->select.dst_port = fuzz_port;
			reply->select.time.real_time = network_time;
			reply->select.time.monotonic_time = network_time;
			reply->select.time.network_time = network_time;
			break;
		case REQ_SEND:
			if (request->send.src_port == fuzz_port)
				fwrite(request->send.data, 1, request->send.len, stdout);
			break;
		case REQ_RECV:
			reply->recv.subnet = 0;
			reply->recv.from = 1;
			reply->recv.src_port = fuzz_port;
			reply->recv.dst_port = fuzz_port;
			reply->recv.len = fread(reply->recv.data, 1, sizeof (reply->recv.data), stdin);
			received = 1;
			break;
		case REQ_SETTIME:
		case REQ_ADJTIMEX:
		case REQ_ADJTIME:
		case REQ_GETREFSAMPLE:
		case REQ_GETREFOFFSETS:
		case REQ_DEREGISTER:
			if (reply)
				memset(reply, 0, replylen);
			break;
		case REQ_REGISTER:
		default:
			assert(0);
	}
}
