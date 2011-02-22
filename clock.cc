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

#include "clock.h"

#define MINSEC 256
#define MAXSEC 2048
#define SHIFT_FLL 2
#define SCALE_FREQ 65536.0e6
#define MAXFREQ_SCALED 32768000
#define MAX_SLEWRATE 500
#define BASE_TICK 10000
#define MAX_TICK (BASE_TICK * 11 / 10)
#define MIN_TICK (BASE_TICK * 9 / 10)

#define MIN_FREQ 0.8
#define MAX_FREQ 1.2

Clock::Clock() {
	time = 0.0;
	freq = 1.0;

	freq_generator = NULL;

	memset(&ntp_timex, 0, sizeof(ntp_timex));
	ntp_timex.tick = BASE_TICK;
	ntp_timex.tolerance = MAXFREQ_SCALED;
	ntp_timex.precision = 1;

	ntp_shift_pll = 4;
	ntp_flags = 0;
	ntp_update_interval = 0;
	ntp_offset = 0.0;
	ntp_slew = 0.0;

	ss_offset = 0;
	ss_slew = 0;
}

Clock::~Clock() {
	if (freq_generator)
		delete freq_generator;
}

double Clock::get_time() const {
	return time;
}

double Clock::get_total_freq() const {
	double timex_freq, adjtime_freq;

	timex_freq = (double)ntp_timex.tick / BASE_TICK + ntp_timex.freq / SCALE_FREQ + ntp_slew;
	adjtime_freq = ss_slew / 1e6;
	return freq * (timex_freq + adjtime_freq);
}

double Clock::get_noslew_freq() const {
	double timex_freq;

	timex_freq = (double)ntp_timex.tick / BASE_TICK + ntp_timex.freq / SCALE_FREQ;
	return freq * timex_freq;
}

double Clock::get_real_interval(double local_interval) const {
	return local_interval / get_total_freq();
}

double Clock::get_local_interval(double real_interval) const {
	return real_interval * get_total_freq();
}

void Clock::set_freq_generator(Generator *gen) {
	if (freq_generator)
		delete freq_generator;
	freq_generator = gen;
}

void Clock::set_freq(double freq) {
	this->freq = freq + 1.0;
	if (!(this->freq > MIN_FREQ && this->freq < MAX_FREQ)) {
		fprintf(stderr, "frequency %e outside allowed range (%.2f, %.2f)\n", this->freq - 1.0, MIN_FREQ - 1.0, MAX_FREQ - 1.0);
		exit(1);
	}
}

void Clock::set_time(double time) {
	this->time = time;
}

void Clock::set_ntp_shift_pll(int shift) {
	ntp_shift_pll = shift;
}

void Clock::set_ntp_flag(int enable, int flag) {
	ntp_flags &= ~flag;
	if (enable)
		ntp_flags |= flag;
}

void Clock::advance(double real_interval) {
	time += get_local_interval(real_interval);
}

void Clock::second_overflow() {
	if (freq_generator)
		set_freq(freq_generator->generate());
	
	if (ntp_timex.status & STA_PLL) {
		ntp_update_interval++;
		ntp_slew = ntp_offset / (1 << (ntp_shift_pll +
			ntp_timex.constant + (ntp_timex.status & STA_NANO ? 0 : 4)));

		if (ntp_slew > MAX_SLEWRATE / 1e6)
			ntp_slew = MAX_SLEWRATE / 1e6;
		else if (ntp_slew < -MAX_SLEWRATE / 1e6)
			ntp_slew = -MAX_SLEWRATE / 1e6;

		ntp_offset -= ntp_slew;

		if (ntp_timex.status & STA_NANO)
			ntp_timex.offset = ntp_offset * 1e9;
		else
			ntp_timex.offset = ntp_offset * 1e6;
	}

	if (ss_offset) {
		if (ss_offset > 0) {
			if (ss_offset > MAX_SLEWRATE) {
				ss_slew = MAX_SLEWRATE;
				ss_offset -= MAX_SLEWRATE;
			} else {
				ss_slew = ss_offset;
				ss_offset = 0;
			}
		} else {
			if (ss_offset < -MAX_SLEWRATE) {
				ss_slew = -MAX_SLEWRATE;
				ss_offset -= -MAX_SLEWRATE;
			} else {
				ss_slew = ss_offset;
				ss_offset = 0;
			}
		}
	} else
		ss_slew = 0;
}

void Clock::update_ntp_offset(long offset) {
	double fll_adj, pll_adj, new_offset, old_offset, tc, t;

	if (ntp_timex.status & STA_FREQHOLD)
		ntp_update_interval = 0;

	if (ntp_timex.status & STA_NANO) {
		new_offset = offset / 1e9;
		tc = 1 << ntp_timex.constant;
	} else {
		new_offset = offset / 1e6;
		tc = 1 << (ntp_timex.constant + 4);
	}

	ntp_timex.offset = offset;
	old_offset = ntp_offset;
	ntp_offset = new_offset;

	if (!(ntp_timex.status & STA_PLL))
		return;

	if (old_offset && ntp_update_interval >= MINSEC &&
		(ntp_timex.status & STA_FLL || ntp_update_interval > MAXSEC)) {
		ntp_timex.status |= STA_MODE;
		if (ntp_flags & CLOCK_NTP_FLL_MODE2)
			fll_adj = (new_offset - old_offset) / (ntp_update_interval * (1 << SHIFT_FLL));
		else
			fll_adj = new_offset / (ntp_update_interval * (1 << SHIFT_FLL));
	} else {
		ntp_timex.status &= ~STA_MODE;
		fll_adj = 0.0;
	}

	if (ntp_flags & CLOCK_NTP_PLL_CLAMP) {
		if (ntp_update_interval > MAXSEC)
			ntp_update_interval = MAXSEC;
		if (ntp_update_interval > tc * (1 << (ntp_shift_pll + 1)))
			ntp_update_interval = tc * (1 << (ntp_shift_pll + 1));
	}

	t = 4 * (1 << ntp_shift_pll) * tc;
	pll_adj = new_offset * ntp_update_interval / (t * t);

	ntp_timex.freq += (fll_adj + pll_adj) * SCALE_FREQ;

	if (ntp_timex.freq > MAXFREQ_SCALED)
		ntp_timex.freq = MAXFREQ_SCALED;
	else if (ntp_timex.freq < -MAXFREQ_SCALED)
		ntp_timex.freq = -MAXFREQ_SCALED;

	ntp_update_interval = 0;
}

int Clock::adjtimex(struct timex *buf) {
	int r = 0;
	struct timex t;

	if (buf->modes & ADJ_FREQUENCY) {
		ntp_timex.freq = buf->freq;
		if (ntp_timex.freq > MAXFREQ_SCALED)
			ntp_timex.freq = MAXFREQ_SCALED;
		else if (ntp_timex.freq < -MAXFREQ_SCALED)
			ntp_timex.freq = -MAXFREQ_SCALED;
	}
	if (buf->modes & ADJ_MAXERROR)
		ntp_timex.maxerror = buf->maxerror;
	if (buf->modes & ADJ_STATUS) {
		if ((buf->status & STA_PLL) && !(ntp_timex.status & STA_PLL))
			ntp_update_interval = 0;
		ntp_timex.status = buf->status & 0xff;
	}
	if (buf->modes & ADJ_TIMECONST)
		ntp_timex.constant = buf->constant;
	if (buf->modes & ADJ_MICRO)
		ntp_timex.status &= ~STA_NANO;
	if (buf->modes & ADJ_NANO)
		ntp_timex.status |= STA_NANO;
	if (buf->modes & ADJ_TICK) {
		if (buf->tick > MAX_TICK || buf->tick < MIN_TICK) {
			r = -1;
		} else
			ntp_timex.tick = buf->tick;
	}

	if ((buf->modes & ADJ_OFFSET_SINGLESHOT) != ADJ_OFFSET_SINGLESHOT) {
		if (buf->modes & ADJ_OFFSET) {
			update_ntp_offset(buf->offset);
		}
	}

	t = ntp_timex;

	if ((buf->modes & ADJ_OFFSET_SINGLESHOT) == ADJ_OFFSET_SINGLESHOT) {
		if ((buf->modes & ADJ_OFFSET_SS_READ) == ADJ_OFFSET_SINGLESHOT) {
			t.offset = ss_offset;
			ss_offset = buf->offset;
		} else {
			t.offset = ss_offset;
		}
	}

	*buf = t;

	return r;
}

int Clock::adjtime(const struct timeval *delta, struct timeval *olddelta) {
	if (olddelta) {
		olddelta->tv_sec = ss_offset / 1000000;
		olddelta->tv_usec = ss_offset % 1000000;
	}
	if (delta)
		ss_offset = delta->tv_sec * 1000000 + delta->tv_usec;
	return 0;
}

Refclock::Refclock() {
	time = 0.0;
	offset = 0.0;
	valid = false;
	offset_generator = NULL;
}

Refclock::~Refclock() {
	if (offset_generator)
		delete offset_generator;
}

void Refclock::set_offset_generator(Generator *gen) {
	if (offset_generator)
		delete offset_generator;
	offset_generator = gen;
}

void Refclock::update(double time, const Clock *clock) {
	if (!offset_generator)
		return;

	this->time = time;
	offset = clock->get_time() - time + offset_generator->generate();
	valid = true;
}

bool Refclock::get_reftime(double *time, double *offset) const {
	*time = this->time;
	*offset = this->offset;
	return valid;
}
