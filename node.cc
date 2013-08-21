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

Node::Node(int index, Network *network) {
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

	if (waiting())
		resume();
	while (process_fd()) {
		assert(!waiting());
	}

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
	char buf[MAX_REQ_SIZE];
	Request_header *h;
	void *data;
	int received;

	received = recv(fd, buf, sizeof (buf), 0);
	if (received < (int)sizeof (Request_header))
		return false;

	h = (Request_header *)buf;
	data = buf + sizeof (Request_header);

	assert(pending_request == 0);
	pending_request = h->request;

#ifdef DEBUG
	printf("received request %ld in node %d at %f\n", h->request, index, clock.get_time());
#endif

	switch (h->request) {
		case REQ_GETTIME:
			process_gettime();
			break;
		case REQ_SETTIME:
			process_settime(data);
			break;
		case REQ_ADJTIMEX:
			process_adjtimex(data);
			break;
		case REQ_ADJTIME:
			process_adjtime(data);
			break;
		case REQ_SELECT:
			process_select(data);
			break;
		case REQ_SEND:
			process_send(data);
			break;
		case REQ_RECV:
			process_recv();
			break;
		case REQ_GETREFTIME:
			process_getreftime();
			break;
		case REQ_GETREFOFFSETS:
			process_getrefoffsets();
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

	sent = send(fd, data, len, 0);
	assert(sent == len);
}


void Node::process_gettime() {
	Reply_gettime r;

	r.time = clock.get_time();
	r.mono_time = clock.get_monotime();
	r.network_time = network->get_time();
	reply(&r, sizeof (r), REQ_GETTIME);
}

void Node::process_settime(void *data) {
	Request_settime *req = (Request_settime *)data;
	Reply_empty rep = { 0 };

	clock.set_time(req->time);
	reply(&rep, sizeof (rep), REQ_SETTIME);
}

void Node::process_adjtimex(void *data) {
	Request_adjtimex *req = (Request_adjtimex *)data;
	Reply_adjtimex rep;
	struct timex *buf = &req->timex;

	rep.ret = clock.adjtimex(buf);
	rep.timex = *buf;
	rep._pad = 0;
	reply(&rep, sizeof (rep), REQ_ADJTIMEX);
}

void Node::process_adjtime(void *data) {
	Request_adjtime *req = (Request_adjtime *)data;
	Reply_adjtime rep;

	clock.adjtime(&req->tv, &rep.tv);
	reply(&rep, sizeof (rep), REQ_ADJTIME);
}

void Node::process_select(void *data) {
	Request_select *req = (Request_select *)data;
	Reply_select rep;

	if (terminate) {
		rep.ret = REPLY_SELECT_TERMINATE;
		rep.port = 0;
		reply(&rep, sizeof (rep), REQ_SELECT);
	} else if (incoming_packets.size() > 0) {
		rep.ret = incoming_packets.back()->broadcast ? REPLY_SELECT_BROADCAST : REPLY_SELECT_NORMAL;
		rep.port = incoming_packets.back()->port;
		reply(&rep, sizeof (rep), REQ_SELECT);
#ifdef DEBUG
		printf("returning select immediately in %d at %f\n", index, clock.get_time());
#endif
	} else {
		select_timeout = req->timeout;
		if (select_timeout < 0.0)
			select_timeout = 0.0;
		select_timeout += clock.get_monotime();
#ifdef DEBUG
		printf("suspending select in %d at %f\n", index, clock.get_time());
#endif
	}
}

void Node::process_send(void *data) {
	Request_send *req = (Request_send *)data;
	Reply_empty rep = { 0 };
	struct Packet *packet;

	assert(req->len <= sizeof (packet->data));

	if (!terminate) {
		packet = new struct Packet;
		packet->broadcast = req->to == (unsigned int)-1;
		packet->from = index;
		packet->to = req->to;
		packet->port = req->port;
		packet->len = req->len;
		memcpy(packet->data, req->data, req->len);
		network->send(packet);
	}

	reply(&rep, sizeof (rep), REQ_SEND);
}

void Node::process_recv() {
	Reply_recv rep;
	struct Packet *packet;

	if (incoming_packets.empty()) {
		rep.from = -1;
		rep.port = 0;
		rep.len = 0;
		memset(rep.data, 0, sizeof (rep.data));
		reply(&rep, sizeof (rep), REQ_RECV);

		return;
	}

	packet = incoming_packets.back();

	rep.from = packet->from;
	rep.port = packet->port;
	rep.len = packet->len;

	assert(packet->len <= sizeof (rep.data));
	memcpy(rep.data, packet->data, packet->len);
	memset(rep.data + packet->len, 0, sizeof (rep.data) - packet->len);
	
	delete packet;

	reply(&rep, sizeof (rep), REQ_RECV);

	incoming_packets.pop_back();
#ifdef DEBUG
	printf("received packet in %d at %f\n", index, clock.get_time());
#endif
}

void Node::receive(struct Packet *packet) {
	if (pending_request == REQ_REGISTER) {
		delete packet;
		return;
	}

	incoming_packets.push_back(packet);

	if (pending_request == REQ_SELECT) {
		Reply_select rep;
		rep.ret = incoming_packets.back()->broadcast ? REPLY_SELECT_BROADCAST : REPLY_SELECT_NORMAL;
		rep.port = incoming_packets.back()->port;
		reply(&rep, sizeof (rep), REQ_SELECT);
#ifdef DEBUG
		printf("resuming select in %d at %f\n", index, clock.get_time());
#endif
	}
}

void Node::process_getreftime() {
	Reply_getreftime r;

	r.valid = refclock.get_reftime(&r.time, &r.offset);
	r._pad = 0;
	reply(&r, sizeof (r), REQ_GETREFTIME);
}

void Node::process_getrefoffsets() {
	Reply_getrefoffsets r;

	refclock.get_refoffsets(r.offsets, REPLY_GETREFOFFSETS_SIZE);
	reply(&r, sizeof (r), REQ_GETREFOFFSETS);
}

void Node::resume() {
	switch (pending_request) {
		case REQ_SELECT:
			if (terminate) {
				Reply_select rep = { REPLY_SELECT_TERMINATE, 0 };
				reply(&rep, sizeof (rep), REQ_SELECT);
			} else if (select_timeout - clock.get_monotime() <= 0.0) {
				assert(select_timeout - clock.get_monotime() > -1e-10);
				Reply_select rep = { REPLY_SELECT_TIMEOUT, 0 };
				reply(&rep, sizeof (rep), REQ_SELECT);
#ifdef DEBUG
				printf("resuming select in %d at %f\n", index, clock.get_time());
#endif
			}
			break;
		case REQ_REGISTER:
			if (start_time - network->get_time() <= 0.0 || terminate) {
				Reply_empty rep = { 0 };
				reply(&rep, sizeof (rep), REQ_REGISTER);
#ifdef DEBUG
				printf("starting %d at %f\n", index, network->get_time());
#endif
			}
			break;
		default:
			assert(0);

	}
}

bool Node::waiting() const {
	return pending_request == REQ_SELECT || pending_request == REQ_REGISTER;
}

double Node::get_timeout() const {
	switch (pending_request) {
		case REQ_SELECT:
			return clock.get_real_interval(select_timeout - clock.get_monotime());
		case REQ_REGISTER:
			return start_time - network->get_time();
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
