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

#ifndef NODE_H
#define NODE_H

#include "protocol.h"
#include "clock.h"

#include <vector>

using namespace std;

class Network;

class Node {
	Clock clock;
	Refclock refclock;
	Clock *refclock_base;
	Network *network;
	int index;
	int fd;
	int pending_request;
	double start_time;
	double select_timeout;
	bool select_read;
	bool terminate;

	vector<struct Packet *> incoming_packets;

	public:
	Node(int index, Network *network);
	~Node();
	void set_fd(int fd);
	int get_fd() const;
	void set_start_time(double time);
	bool process_fd();
	void reply(void *data, int len, int request);
	void process_gettime();
	void process_settime(Request_settime *req);
	void process_adjtimex(Request_adjtimex *req);
	void process_adjtime(Request_adjtime *req);
	void try_select();
	void process_select(Request_select *req);
	void process_send(Request_send *req);
	void process_recv();
	void process_getrefsample();
	void process_getrefoffsets();

	void receive(struct Packet *packet);
	void resume();
	bool waiting() const;
	bool finished() const;

	double get_timeout() const;
	Clock *get_clock();
	Refclock *get_refclock();
	void set_refclock_base(Clock *clock);
};

#endif
