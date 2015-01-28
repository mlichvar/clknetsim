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

#include "sysheaders.h"
#include "network.h"

Packet_queue::Packet_queue() {
}

Packet_queue::~Packet_queue() {
	while (!queue.empty()) {
		delete queue.back();
		queue.pop_back();
	}
}

void Packet_queue::insert(struct Packet *packet) {
	deque<struct Packet *>::iterator i;

	for (i = queue.begin(); i < queue.end(); i++)
		if (packet->receive_time < (*i)->receive_time)
			break;
	queue.insert(i, packet);
}

struct Packet *Packet_queue::dequeue() {
	struct Packet *ret;

	assert(!queue.empty());
	ret = queue.front();
	queue.pop_front();

	return ret;
}

double Packet_queue::get_timeout(double time) const {
	if (!queue.empty()) {
		return queue[0]->receive_time - time;
	}
	return 1e20;
}

Network::Network(const char *socket, unsigned int n, unsigned int subnets, unsigned int rate) {
       	time = 0.0;
	this->subnets = subnets;
	socket_name = socket;
	update_rate = rate;
	update_count = 0;
	offset_log = NULL;
	freq_log = NULL;
	rawfreq_log = NULL;
	packet_log = NULL;

	assert(n > 0);

	while (nodes.size() < n)
		nodes.push_back(new Node(nodes.size(), this));

	stats.resize(n);
	link_delays.resize(n * n);
}

Network::~Network() {
	while (!nodes.empty()) {
		delete nodes.back();
		nodes.pop_back();
	}

	while (!link_delays.empty()) {
		delete link_delays.back();
		link_delays.pop_back();
	}

	unlink(socket_name);

	if (offset_log)
		fclose(offset_log);
	if (freq_log)
		fclose(freq_log);
	if (rawfreq_log)
		fclose(rawfreq_log);
	if (packet_log)
		fclose(packet_log);
}


bool Network::prepare_clients() {
	struct sockaddr_un s;
	int sockfd, fd;
        unsigned int i;

	s.sun_family = AF_UNIX;
	snprintf(s.sun_path, sizeof (s.sun_path), "%s", socket_name);

	sockfd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (sockfd < 0) {
		fprintf(stderr, "socket() failed\n");
		return false;
	}

	unlink(socket_name);
	if (bind(sockfd, (struct sockaddr *)&s, sizeof (s)) < 0) {
		fprintf(stderr, "bind() failed\n");
		return false;
	}

	if (listen(sockfd, nodes.size()) < 0) {
		fprintf(stderr, "listen() failed\n");
		return false;
	}

	for (i = 0; i < nodes.size(); i++) {
		Request_packet req;
		unsigned int node;

		fprintf(stderr, "\rWaiting for %u clients...", (unsigned int)nodes.size() - i);
		fd = accept(sockfd, NULL, NULL);
		if (fd < 0) {
			fprintf(stderr, "accept() failed\n");
			return false;
		}

		if (recv(fd, &req, sizeof (req), 0) != offsetof(Request_packet, data) +
				sizeof (Request_register) || req.header.request != REQ_REGISTER) {
			fprintf(stderr, "client didn't register correctly.\n");
			return false;
		}
		node = req.data._register.node;
		assert(node < nodes.size() && nodes[node]->get_fd() < 0);
		nodes[node]->set_fd(fd);
	}
	fprintf(stderr, "done\n");

	close(sockfd);

	update();

	return true;
}

Node *Network::get_node(unsigned int node) {
	assert(node < nodes.size());
	return nodes[node];
}

void Network::set_link_delay_generator(unsigned int from, unsigned int to, Generator *generator) {
	unsigned int i;

	assert(from < nodes.size() && to < nodes.size());

	i = from * nodes.size() + to;
	if (link_delays[i])
		delete link_delays[i];
	link_delays[i] = generator;
}

bool Network::run(double time_limit) {
	int i, n = nodes.size(), waiting;
	bool pending_update;
	struct pollfd pollfds[n];
	double min_timeout, timeout, next_update;

	for (i = 0; i < n; i++) {
		pollfds[i].fd = nodes[i]->get_fd();
		pollfds[i].events = !nodes[i]->finished() ? POLLIN : 0;
		pollfds[i].revents = 0;
	}

	while (time < time_limit) {
		for (i = 0, waiting = 0; i < n; i++)
			if (nodes[i]->waiting())
				waiting++;
			else 
				stats[i].update_wakeup_stats();

		while (waiting < n) {
#if 1
			if (poll(pollfds, n, -1) <= 0) {
				fprintf(stderr, "poll() error.\n");
				return false;
			}
#else
			for (i = 0; i < n; i++)
				if (!nodes[i]->waiting()) {
					pollfds[i].revents = POLLIN;
					break;
				}
#endif
			for (i = 0; i < n; i++) {
				if (!(pollfds[i].revents & POLLIN))
					continue;
				pollfds[i].revents = 0;

				assert(!nodes[i]->waiting());
				if (!nodes[i]->process_fd()) {
					fprintf(stderr, "client %d failed.\n", i + 1);
					return false;
				}
				if (nodes[i]->finished())
					pollfds[i].events = 0;
				if (nodes[i]->waiting())
					waiting++;
			}
		}

		do {
			min_timeout = nodes[0]->get_timeout();
			for (i = 1; i < n; i++) {
				timeout = nodes[i]->get_timeout();
				if (min_timeout > timeout)
					min_timeout = timeout;
			}

			timeout = packet_queue.get_timeout(time);
			if (timeout <= min_timeout)
				min_timeout = timeout;

			next_update = floor(time) + (double)(update_count + 1) / update_rate;
			timeout = next_update - time;
			if (timeout <= min_timeout) {
				min_timeout = timeout;
				pending_update = true;
			} else
				pending_update = false;

			//min_timeout += 1e-12;
			assert(min_timeout >= 0.0);

			if (pending_update)
				time = next_update;
			else
				time += min_timeout;

			for (i = 0; i < n; i++)
				nodes[i]->get_clock()->advance(min_timeout);

			if (pending_update)
				update();
		} while (pending_update && time < time_limit);

		for (i = 0; i < n; i++)
			nodes[i]->resume();

		while (packet_queue.get_timeout(time) <= 0) {
			assert(packet_queue.get_timeout(time) > -1e-10);
			struct Packet *packet = packet_queue.dequeue();
			nodes[packet->to]->receive(packet);
		}
	}

	return true;
}

void Network::update() {
	int i, n = nodes.size();

	update_count++;
	update_count %= update_rate;

	for (i = 0; i < n; i++) {
		nodes[i]->get_clock()->update(update_count == 0);
		nodes[i]->get_refclock()->update(time, nodes[i]->get_clock());
	}

	update_clock_stats();
}

void Network::update_clock_stats() {
	int i, n = nodes.size();

	if (offset_log) {
		for (i = 0; i < n; i++)
			fprintf(offset_log, "%.9f%c", nodes[i]->get_clock()->get_real_time() - time, i + 1 < n ? '\t' : '\n');
	}
	if (freq_log) {
		for (i = 0; i < n; i++)
			fprintf(freq_log, "%e%c", nodes[i]->get_clock()->get_total_freq() - 1.0, i + 1 < n ? '\t' : '\n');
	}
	if (rawfreq_log) {
		for (i = 0; i < n; i++)
			fprintf(rawfreq_log, "%e%c", nodes[i]->get_clock()->get_raw_freq() - 1.0, i + 1 < n ? '\t' : '\n');
	}

	for (i = 0; i < n; i++)
		stats[i].update_clock_stats(nodes[i]->get_clock()->get_real_time() - time,
				nodes[i]->get_clock()->get_total_freq() - 1.0,
				nodes[i]->get_clock()->get_raw_freq() - 1.0);
}

void Network::open_offset_log(const char *log) {
	offset_log = fopen(log, "w");
}

void Network::open_freq_log(const char *log) {
	freq_log = fopen(log, "w");
}

void Network::open_rawfreq_log(const char *log) {
	rawfreq_log = fopen(log, "w");
}

void Network::open_packet_log(const char *log) {
	packet_log = fopen(log, "w");
}

void Network::print_stats(int verbosity) const {
	int i, n = nodes.size();

	if (verbosity <= 0)
		return;

	for (i = 0; i < n; i++) {
		if (verbosity > 1)
			printf("\n---------------------- Node %d ----------------------\n\n", i + 1);
		stats[i].print(verbosity);
	}
	if (verbosity == 1)
		printf("\n");
}

void Network::reset_stats() {
	int i, n = nodes.size();

	for (i = 0; i < n; i++)
		stats[i].reset();
}

void Network::reset_clock_stats() {
	int i, n = nodes.size();

	for (i = 0; i < n; i++)
		stats[i].reset_clock_stats();
}

void Network::send(struct Packet *packet) {
	double delay = -1.0;
	unsigned int i;

	/* broadcast */
	if (packet->to == (unsigned int)-1) {
		for (i = 0; i < nodes.size(); i++) {
			struct Packet *p;

			if (i == packet->from)
				continue;

			p = new struct Packet;
			memcpy(p, packet, sizeof (struct Packet));
			p->to = i;

			send(p);
		}

		delete packet;
		return;
	}

	assert(packet->to < nodes.size() && packet->from < nodes.size() &&
			packet->subnet < subnets);

	i = packet->from * nodes.size() + packet->to;

	if (link_delays[i]) {
		link_delay_variables["time"] = time;
		link_delay_variables["from"] = packet->from + 1;
		link_delay_variables["to"] = packet->to + 1;
		link_delay_variables["subnet"] = packet->subnet + 1;
		link_delay_variables["port"] = packet->dst_port;
		link_delay_variables["length"] = packet->len;

		delay = link_delays[i]->generate(&link_delay_variables);
	}

	stats[packet->from].update_packet_stats(false, time, delay);

	if (packet_log)
		fprintf(packet_log, "%e\t%d\t%d\t%e\t%d\t%d\t%d\n", time,
				packet->from + 1, packet->to + 1, delay,
				packet->src_port, packet->dst_port,
				packet->subnet + 1);

	if (delay > 0.0) {
		packet->receive_time = time + delay;
		packet_queue.insert(packet);
		stats[packet->to].update_packet_stats(true, time + delay, delay);
#ifdef DEBUG
		printf("sending packet from %d to %d:%d:%d at %f delay %f \n",
				packet->from, packet->subnet, packet->to,
				packet->dst_port, time, delay);
#endif
	} else {
#ifdef DEBUG
		printf("dropping packet from %d to %d:%d:%d at %f\n",
				packet->from, packet->subnet, packet->to,
				packet->dst_port, time);
#endif
		delete packet;
	}
}

double Network::get_time() const {
	return time;
}

unsigned int Network::get_subnets() const {
	return subnets;
}
