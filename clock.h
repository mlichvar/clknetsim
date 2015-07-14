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

#ifndef CLOCK_H
#define CLOCK_H

#include "sysheaders.h"

#include "generator.h"

#define CLOCK_NTP_FLL_MODE2 0x1
#define CLOCK_NTP_PLL_CLAMP 0x2

class Clock {
	double time;
	double mono_time;
	double freq;

	Generator *freq_generator;
	Generator *step_generator;

	long base_tick;

	struct timex ntp_timex;
	int ntp_state;
	int ntp_shift_pll;
	int ntp_flags;
	long ntp_update_interval;
	double ntp_offset;
	double ntp_slew;

	long ss_offset;
	long ss_slew;

public:
	Clock();
	~Clock();
	double get_real_time() const;
	double get_monotonic_time() const;
	double get_total_freq() const;
	double get_raw_freq() const;
	double get_true_interval(double local_interval) const;
	double get_local_interval(double true_interval) const;

	void set_freq_generator(Generator *gen);
	void set_step_generator(Generator *gen);
	void set_freq(double freq);
	void set_time(double time);
	void step_time(double step);
	void set_ntp_shift_pll(int shift);
	void set_ntp_flag(int enable, int flag);

	void advance(double real_interval);
	void update(bool second);

	void update_ntp_offset(long offset);
	int adjtimex(struct timex *buf);
	int adjtime(const struct timeval *delta, struct timeval *olddelta);
};

class Refclock {
	double time;
	double offset;
	bool generate;
	bool valid;

	Generator *offset_generator;
public:
	Refclock();
	~Refclock();
	void set_offset_generator(Generator *gen);
	void update(double time, const Clock *clock);
	void set_generation(bool enable);
	bool get_sample(double *time, double *offset) const;
	void get_offsets(double *offsets, int size);
};

#endif
