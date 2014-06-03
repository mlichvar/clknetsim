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

#ifndef STATS_H
#define STATS_H

#include "clock.h"

class Stats {
	double offset_sum2;
	double offset_abs_sum;
	double offset_sum;
	double offset_abs_max;
	double freq_sum2;
	double freq_abs_sum;
	double freq_sum;
	double freq_abs_max;
	double rawfreq_sum2;
	double rawfreq_abs_sum;
	double rawfreq_sum;
	double rawfreq_abs_max;
	unsigned long samples;

	double packets_in_sum2;
	double packets_out_sum2;
	unsigned long packets_in;
	unsigned long packets_out;
	double packets_in_time_last;
	double packets_out_time_last;
	double packets_in_int_sum;
	double packets_out_int_sum;
	double packets_in_int_min;
	double packets_out_int_min;

	unsigned long wakeups_int_sum;
	unsigned long wakeups;

	public:
	Stats();
	~Stats();
	void reset();
	void reset_clock_stats();
	void update_clock_stats(double offset, double freq, double rawfreq);
	void update_packet_stats(bool incoming, double time, double delay);
	void update_wakeup_stats();
	void print(int verbosity) const;
};

#endif
