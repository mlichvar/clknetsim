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

#include "node.h"
#include "network.h"
#include "protocol.h"
#include "sysheaders.h"

Node::Node(int index, Network *network) {
	this->refclock_base = NULL;
	this->network = network;
	this->index = index;
	fd = -1;
	pending_request = REQ_REGISTER;
	start_time = 0.0;
	terminate = false;
}

Node::~Node() {
	while (!incoming_packets.empty()) {
		delete incoming_packets.back();
		incoming_packets.pop_back();
	}

	terminate = true;

	do {
		if (waiting())
			resume();
	} while (process_fd());

	if (fd >= 0)
		close(fd);
}

void Node::set_fd(int fd) {
	this->fd = fd;
}

int Node::get_fd() const {
	return fd;
}

void Node::set_start_time(double time) {
	start_time = time;
}

bool Node::process_fd() {
	Request_packet request;
	int received, reqlen;

	received = recv(fd, &request, sizeof (request), 0);
	if (received < 0)
		fprintf(stderr, "recv() failed: %s\n", strerror(errno));
	if (received < (int)sizeof (request.header))
		return false;

	reqlen = received - (int)offsetof(Request_packet, data);

	assert(pending_request == 0);
	pending_request = request.header.request;

#ifdef DEBUG
	printf("received request %d in node %d at %f\n",
			pending_request, index, clock.get_real_time());
#endif

	switch (pending_request) {
		case REQ_GETTIME:
			assert(reqlen == 0);
			process_gettime();
			break;
		case REQ_SETTIME:
			assert(reqlen == sizeof (Request_settime));
			process_settime(&request.data.settime);
			break;
		case REQ_ADJTIMEX:
			assert(reqlen == sizeof (Request_adjtimex));
			process_adjtimex(&request.data.adjtimex);
			break;
		case REQ_ADJTIME:
			assert(reqlen == sizeof (Request_adjtime));
			process_adjtime(&request.data.adjtime);
			break;
		case REQ_SELECT:
			assert(reqlen == sizeof (Request_select));
			process_select(&request.data.select);
			break;
		case REQ_SEND:
			/* request with variable length */
			assert(reqlen >= (int)offsetof(Request_send, data) &&
					reqlen <= (int)sizeof (Request_send));
			assert(request.data.send.len <= sizeof (request.data.send.data));
			assert((int)(request.data.send.len + offsetof(Request_send, data)) <= reqlen);
			process_send(&request.data.send);
			break;
		case REQ_RECV:
			assert(reqlen == 0);
			process_recv();
			break;
		case REQ_GETREFSAMPLE:
			assert(reqlen == 0);
			process_getrefsample();
			break;
		case REQ_GETREFOFFSETS:
			assert(reqlen == 0);
			process_getrefoffsets();
			break;
		case REQ_DEREGISTER:
			assert(reqlen == 0);
			break;
		default:
			assert(0);
	}

	return true;
}

void Node::reply(void *data, int len, int request) {
	int sent;

	assert(request == pending_request);
	pending_request = 0;

	if (data) {
		sent = send(fd, data, len, 0);
		assert(sent == len);
	}
}


void Node::process_gettime() {
	Reply_gettime r;

	r.real_time = clock.get_real_time();
	r.monotonic_time = clock.get_monotonic_time();
	r.network_time = network->get_time();
	r.freq_error = clock.get_total_freq() - 1.0;
	reply(&r, sizeof (r), REQ_GETTIME);
}

void Node::process_settime(Request_settime *req) {
	clock.set_time(req->time);
	reply(NULL, 0, REQ_SETTIME);
}

void Node::process_adjtimex(Request_adjtimex *req) {
	Reply_adjtimex rep;
	struct timex *buf = &req->timex;

	rep.ret = clock.adjtimex(buf);
	rep.timex = *buf;
	rep._pad = 0;
	reply(&rep, sizeof (rep), REQ_ADJTIMEX);
}

void Node::process_adjtime(Request_adjtime *req) {
	Reply_adjtime rep;

	clock.adjtime(&req->tv, &rep.tv);
	reply(&rep, sizeof (rep), REQ_ADJTIME);
}

void Node::try_select() {
	Reply_select rep = {-1, 0, 0};

	if (terminate) {
		rep.ret = REPLY_SELECT_TERMINATE;
#ifdef DEBUG
		printf("select returned on termination in %d at %f\n",
				index, clock.get_real_time());
#endif
	} else if (select_timeout - clock.get_monotonic_time() <= 0.0) {
		assert(select_timeout - clock.get_monotonic_time() > -1e-10);
		rep.ret = REPLY_SELECT_TIMEOUT;
#ifdef DEBUG
		printf("select returned on timeout in %d at %f\n", index, clock.get_real_time());
#endif
	} else if (select_read && incoming_packets.size() > 0) {
		rep.ret = incoming_packets.back()->broadcast ?
			REPLY_SELECT_BROADCAST :
			REPLY_SELECT_NORMAL;
		rep.type = incoming_packets.back()->type;
		rep.subnet = incoming_packets.back()->subnet;
		rep.from = incoming_packets.back()->from;
		rep.src_port = incoming_packets.back()->src_port;
		rep.dst_port = incoming_packets.back()->dst_port;
#ifdef DEBUG
		printf("select returned for packet in %d at %f\n", index, clock.get_real_time());
#endif
	}

	if (rep.ret >= 0) {
		rep.time.real_time = clock.get_real_time();
		rep.time.monotonic_time = clock.get_monotonic_time();
		rep.time.network_time = network->get_time();
		rep.time.freq_error = clock.get_total_freq() - 1.0;
		reply(&rep, sizeof (rep), REQ_SELECT);
	}
}

void Node::process_select(Request_select *req) {
	if (req->timeout < 0.0)
		req->timeout = 0.0;
	select_timeout = clock.get_monotonic_time() + req->timeout;
	select_read = req->read;
#ifdef DEBUG
	printf("select called with timeout %f read %d in %d at %f\n",
			req->timeout, req->read, index, clock.get_real_time());
#endif
	try_select();
}

void Node::process_send(Request_send *req) {
	struct Packet *packet;

	if (!terminate) {
		packet = new struct Packet;
		packet->type = req->type;
		packet->broadcast = req->to == (unsigned int)-1;
		packet->subnet = req->subnet;
		packet->from = index;
		packet->to = req->to;
		packet->src_port = req->src_port;
		packet->dst_port = req->dst_port;
		packet->len = req->len;
		memcpy(packet->data, req->data, req->len);
		network->send(packet);
	}

	reply(NULL, 0, REQ_SEND);
}

void Node::process_recv() {
	Reply_recv rep;
	struct Packet *packet;

	if (incoming_packets.empty()) {
		rep.type = MSG_TYPE_NO_MSG;
		rep.subnet = 0;
		rep.from = -1;
		rep.src_port = 0;
		rep.dst_port = 0;
		rep.len = 0;
		reply(&rep, offsetof (Reply_recv, data), REQ_RECV);

		return;
	}

	packet = incoming_packets.back();

	rep.type = packet->type;
	rep.subnet = packet->subnet;
	rep.from = packet->from;
	rep.src_port = packet->src_port;
	rep.dst_port = packet->dst_port;
	rep.len = packet->len;

	assert(packet->len <= sizeof (rep.data));
	memcpy(rep.data, packet->data, packet->len);
	
	delete packet;

	reply(&rep, offsetof (Reply_recv, data) + rep.len, REQ_RECV);

	incoming_packets.pop_back();
#ifdef DEBUG
	printf("received packet in %d at %f\n", index, clock.get_real_time());
#endif
}

void Node::receive(struct Packet *packet) {
	if (pending_request == REQ_REGISTER || pending_request == REQ_DEREGISTER) {
		delete packet;
		return;
	}

	incoming_packets.insert(incoming_packets.begin(), packet);

	if (pending_request == REQ_SELECT)
		try_select();
}

void Node::process_getrefsample() {
	Reply_getrefsample r;

	refclock.set_generation(true);
	r.valid = refclock.get_sample(&r.time, &r.offset);
	assert(!refclock_base);
	r._pad = 0;
	reply(&r, sizeof (r), REQ_GETREFSAMPLE);
}

void Node::process_getrefoffsets() {
	Reply_getrefoffsets r;

	if (refclock_base) {
		r.size = 1;
		refclock.get_offsets(r.offsets, r.size);
		r.offsets[0] += network->get_time() - refclock_base->get_real_time();
	} else {
		r.size = MAX_GETREFOFFSETS_SIZE;
		refclock.get_offsets(r.offsets, r.size);
	}
	r._pad = 0;
	reply(&r, offsetof(Reply_getrefoffsets, offsets) +
		  sizeof (r.offsets[0]) * r.size, REQ_GETREFOFFSETS);
}

void Node::resume() {
	switch (pending_request) {
		case REQ_SELECT:
			try_select();
			break;
		case REQ_REGISTER:
			if (start_time - network->get_time() <= 0.0 || terminate) {
				Reply_register rep;
				rep.subnets = network->get_subnets();
				reply(&rep, sizeof (rep), REQ_REGISTER);
#ifdef DEBUG
				printf("starting %d at %f\n", index, network->get_time());
#endif
			}
			break;
		case REQ_DEREGISTER:
			break;
		default:
			assert(0);

	}
}

bool Node::waiting() const {
	return pending_request == REQ_SELECT ||
		pending_request == REQ_REGISTER ||
		pending_request == REQ_DEREGISTER;
}

bool Node::finished() const {
	return pending_request == REQ_DEREGISTER;
}

double Node::get_timeout() const {
	switch (pending_request) {
		case REQ_SELECT:
			return clock.get_true_interval(select_timeout - clock.get_monotonic_time());
		case REQ_REGISTER:
			return start_time - network->get_time();
		case REQ_DEREGISTER:
			return 10.0;
		default:
			assert(0);
	}
}

Clock *Node::get_clock() {
	return &clock;
}

Refclock *Node::get_refclock() {
	return &refclock;
}

void Node::set_refclock_base(Clock *clock) {
	refclock_base = clock;
}
