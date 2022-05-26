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

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "sysheaders.h"

#define REQ_REGISTER 1
#define REQ_GETTIME 2
#define REQ_SETTIME 3
#define REQ_ADJTIMEX 4
#define REQ_ADJTIME 5
#define REQ_SELECT 6
#define REQ_SEND 7
#define REQ_RECV 8
#define REQ_GETREFSAMPLE 9
#define REQ_GETREFOFFSETS 10
#define REQ_DEREGISTER 11

struct Request_header {
	int request;
	int _pad;
};

struct Request_register {
	unsigned int node;
};

struct Reply_register {
	unsigned int subnets;
};

struct Reply_gettime {
	double real_time;
	double monotonic_time;
	double network_time;
	double freq_error;
};

struct Request_settime {
	double time;
};

struct Request_adjtimex {
	struct timex timex;
};

struct Reply_adjtimex {
	int ret;
	int _pad;
	struct timex timex;
};

struct Request_adjtime {
	struct timeval tv;
};

struct Reply_adjtime {
	struct timeval tv;
};

struct Request_select {
	double timeout;
	int read;
	int _pad;
};

#define REPLY_SELECT_TIMEOUT 0
#define REPLY_SELECT_NORMAL 1
#define REPLY_SELECT_BROADCAST 2
#define REPLY_SELECT_TERMINATE 3

struct Reply_select {
	int ret;
	unsigned int type; /* for NORMAL */
	unsigned int subnet; /* for NORMAL or BROADCAST */
	unsigned int from; /* for NORMAL or BROADCAST */
	unsigned int src_port; /* for NORMAL or BROADCAST */
	unsigned int dst_port; /* for NORMAL or BROADCAST */
	struct Reply_gettime time;
};

#define MAX_PACKET_SIZE 4000

#define MSG_TYPE_NO_MSG 0
#define MSG_TYPE_UDP_DATA 1
#define MSG_TYPE_TCP_CONNECT 2
#define MSG_TYPE_TCP_DATA 3
#define MSG_TYPE_TCP_DISCONNECT 4

struct Request_send {
	unsigned int type;
	unsigned int subnet;
	unsigned int to;
	unsigned int src_port;
	unsigned int dst_port;
	unsigned int len;
	char data[MAX_PACKET_SIZE];
};

struct Reply_recv {
	unsigned int type;
	unsigned int subnet;
	unsigned int from;
	unsigned int src_port;
	unsigned int dst_port;
	unsigned int len;
	char data[MAX_PACKET_SIZE];
};

struct Reply_getrefsample {
	double time;
	double offset;
	int valid;
	int _pad;
};

#define MAX_GETREFOFFSETS_SIZE 1024

struct Reply_getrefoffsets {
	unsigned int size;
	int _pad;
	double offsets[MAX_GETREFOFFSETS_SIZE];
};

union Request_data {
	struct Request_register _register;
	struct Request_settime settime;
	struct Request_adjtimex adjtimex;
	struct Request_adjtime adjtime;
	struct Request_select select;
	struct Request_send send;
};

union Reply_data {
	struct Reply_register _register;
	struct Reply_gettime gettime;
	struct Reply_adjtimex adjtimex;
	struct Reply_adjtime adjtime;
	struct Reply_select select;
	struct Reply_recv recv;
	struct Reply_getrefsample getrefsample;
	struct Reply_getrefoffsets getrefoffsets;
};

struct Request_packet {
	struct Request_header header;
	union Request_data data;
};

struct Reply_packet {
	union Reply_data data;
};

#endif
