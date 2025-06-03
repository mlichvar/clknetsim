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

#ifndef NETWORK_H
#define NETWORK_H

#include <vector>
#include <deque>

using namespace std;

#include "node.h"
#include "stats.h"

struct Packet {
	double receive_time;
	double delay;
	int broadcast;
	unsigned int type;
	unsigned int subnet;
	unsigned int from;
	unsigned int to;
	unsigned int src_port;
	unsigned int dst_port;
	unsigned int len;
	char data[MAX_PACKET_SIZE];
};

class Packet_queue {
	deque<Packet *> queue;
	public:
	Packet_queue();
	~Packet_queue();
	void insert(struct Packet *packet);
	struct Packet *dequeue();
	double get_timeout(double time) const;
};

class Network {
	double time;
	unsigned int subnets;
	unsigned int update_rate;
	unsigned int update_count;

	const char *socket_name;
	const char *update_executable;
	vector<Node *> nodes;
	vector<Generator *> link_delays;
	vector<Generator *> link_corrections;
	vector<Stats> stats;
	
	Generator_variables link_delay_variables;
	Generator_variables link_correction_variables;

	Packet_queue packet_queue;

	FILE *offset_log;
	FILE *freq_log;
	FILE *rawfreq_log;
	FILE *packet_log;

	void update();
	void update_clock_stats();
	void write_correction(struct Packet *packet, double correction);

	public:
	Network(const char *socket, const char *executable, unsigned int n, unsigned int s, unsigned int rate);
	~Network();
	bool prepare_clients();
	Node *get_node(unsigned int node);
	void set_link_delay_generator(unsigned int from, unsigned int to, Generator *generator);
	void set_link_correction_generator(unsigned int from, unsigned int to, Generator *generator);
	bool run(double time_limit);
	void open_offset_log(const char *log);
	void open_freq_log(const char *log);
	void open_rawfreq_log(const char *log);
	void open_packet_log(const char *log);
	void print_stats(int verbosity) const;
	void reset_stats();
	void reset_clock_stats();

	void send(struct Packet *packet);
	double get_time() const;
	unsigned int get_subnets() const;
};

#endif
