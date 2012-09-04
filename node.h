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
	Network *network;
	int index;
	int fd;
	int pending_request;
	double select_timeout;
	double start_time;

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
	void process_settime(void *data);
	void process_adjtimex(void *data);
	void process_adjtime(void *data);
	void process_select(void *data);
	void process_send(void *data);
	void process_recv();
	void process_getreftime();
	void process_getrefoffsets();

	void receive(struct Packet *packet);
	void resume();
	bool waiting() const;

	double get_timeout() const;
	Clock *get_clock();
	Refclock *get_refclock();
};

#endif
