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
#define MAXTIMECONST 10
#define MAXMAXERROR 16000000
#define MAXERROR_RATE 500
#define SHIFT_FLL 2
#define SCALE_FREQ 65536.0e6
#define MAXFREQ_SCALED 32768000
#define MAX_SLEWRATE 500
#define MAX_TICK(base_tick) ((base_tick) * 11 / 10)
#define MIN_TICK(base_tick) ((base_tick) * 9 / 10)

#define MIN_FREQ 0.8
#define MAX_FREQ 1.2

Clock::Clock() {
	time = 0.0;
	mono_time = 0.0;
	freq = 1.0;

	freq_generator = NULL;
	step_generator = NULL;

	base_tick = sysconf(_SC_CLK_TCK);
	assert(base_tick > 0);
	base_tick = (1000000 + base_tick / 2) / base_tick;

	memset(&ntp_timex, 0, sizeof(ntp_timex));
	ntp_timex.tick = base_tick;
	ntp_timex.tolerance = MAXFREQ_SCALED;
	ntp_timex.precision = 1;
	ntp_timex.maxerror = MAXMAXERROR;
	ntp_timex.esterror = MAXMAXERROR;
	ntp_timex.status = STA_UNSYNC;

	ntp_state = TIME_OK;

	/* in Linux kernel SHIFT_PLL is 2 since 2.6.31 */
	ntp_shift_pll = 2;
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
	if (step_generator)
		delete step_generator;
}

double Clock::get_real_time() const {
	return time;
}

double Clock::get_monotonic_time() const {
	return mono_time;
}

double Clock::get_total_freq() const {
	double timex_freq, adjtime_freq;

	timex_freq = (double)ntp_timex.tick / base_tick + ntp_timex.freq / SCALE_FREQ + ntp_slew;
	adjtime_freq = ss_slew / 1e6;
	return freq * (timex_freq + adjtime_freq);
}

double Clock::get_raw_freq() const {
	double timex_freq;

	timex_freq = (double)ntp_timex.tick / base_tick + ntp_timex.freq / SCALE_FREQ;
	return freq * timex_freq;
}

double Clock::get_true_interval(double local_interval) const {
	return local_interval / get_total_freq();
}

double Clock::get_local_interval(double true_interval) const {
	return true_interval * get_total_freq();
}

void Clock::set_freq_generator(Generator *gen) {
	if (freq_generator)
		delete freq_generator;
	freq_generator = gen;
}

void Clock::set_step_generator(Generator *gen) {
	if (step_generator)
		delete step_generator;
	step_generator = gen;
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

void Clock::step_time(double step) {
	this->time += step;
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
	double local_interval = get_local_interval(real_interval); 

	time += local_interval;
	mono_time += local_interval;
}

void Clock::update(bool second) {
	if (freq_generator)
		set_freq(freq_generator->generate(NULL));
	if (step_generator)
		step_time(step_generator->generate(NULL));
	
	if (!second)
		return;

	if (ntp_timex.status & STA_PLL) {
		ntp_update_interval++;
		ntp_slew = ntp_offset / (1 << (ntp_shift_pll +
			ntp_timex.constant));

#if 0
		if (ntp_slew > MAX_SLEWRATE / 1e6)
			ntp_slew = MAX_SLEWRATE / 1e6;
		else if (ntp_slew < -MAX_SLEWRATE / 1e6)
			ntp_slew = -MAX_SLEWRATE / 1e6;
#endif

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

	ntp_timex.maxerror += MAXERROR_RATE;
	if (ntp_timex.maxerror >= MAXMAXERROR) {
		ntp_timex.maxerror = MAXMAXERROR;
		ntp_timex.status |= STA_UNSYNC;
	}

	switch (ntp_state) {
		case TIME_OK:
			if (ntp_timex.status & STA_INS)
				ntp_state = TIME_INS;
			else if (ntp_timex.status & STA_DEL)
				ntp_state = TIME_DEL;
			break;
		case TIME_INS:
			if ((time_t)(time + 0.5) % (24 * 3600) <= 1) {
				time -= 1.0;
				ntp_timex.tai += 1.0;
				ntp_state = TIME_OOP;
			} else if (!(ntp_timex.status & STA_INS)) {
				ntp_state = TIME_OK;
			}
			break;
		case TIME_DEL:
			if ((time_t)(time + 1.0 + 0.5) % (24 * 3600) <= 1) {
				time += 1.0;
				ntp_timex.tai -= 1.0;
				ntp_state = TIME_WAIT;
			} else if (!(ntp_timex.status & STA_DEL)) {
				ntp_state = TIME_OK;
			}
			break;
		case TIME_OOP:
			ntp_state = TIME_WAIT;
			break;
		case TIME_WAIT:
			if (!(ntp_timex.status & (STA_INS | STA_DEL)))
				ntp_state = TIME_OK;
			break;
		default:
			assert(0);
	}
}

void Clock::update_ntp_offset(long offset) {
	double fll_adj, pll_adj, new_offset, old_offset, tc, t;

	if (ntp_timex.status & STA_FREQHOLD)
		ntp_update_interval = 0;

	if (ntp_timex.status & STA_NANO)
		new_offset = offset / 1e9;
	else
		new_offset = offset / 1e6;

	tc = 1 << ntp_timex.constant;
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
	int r = ntp_state;
	struct timex t;

	if (buf->modes & ADJ_FREQUENCY) {
		ntp_timex.freq = buf->freq;
		if (ntp_timex.freq > MAXFREQ_SCALED)
			ntp_timex.freq = MAXFREQ_SCALED;
		else if (ntp_timex.freq < -MAXFREQ_SCALED)
			ntp_timex.freq = -MAXFREQ_SCALED;
	}
	if (buf->modes & ADJ_MAXERROR) {
		ntp_timex.maxerror = buf->maxerror;
		if (ntp_timex.maxerror > MAXMAXERROR)
			ntp_timex.maxerror = MAXMAXERROR;
		if (ntp_timex.maxerror < 0)
			ntp_timex.maxerror = 0;
	}
	if (buf->modes & ADJ_ESTERROR) {
		ntp_timex.esterror = buf->esterror;
		if (ntp_timex.esterror > MAXMAXERROR)
			ntp_timex.esterror = MAXMAXERROR;
		if (ntp_timex.esterror < 0)
			ntp_timex.esterror = 0;
	}
	if (buf->modes & ADJ_STATUS) {
		if ((buf->status & STA_PLL) && !(ntp_timex.status & STA_PLL))
			ntp_update_interval = 0;
		ntp_timex.status = buf->status & 0xff;
	}
	if (buf->modes & ADJ_MICRO)
		ntp_timex.status &= ~STA_NANO;
	if (buf->modes & ADJ_NANO)
		ntp_timex.status |= STA_NANO;
	if (buf->modes & ADJ_TIMECONST) {
		ntp_timex.constant = buf->constant;
		if (!(ntp_timex.status & STA_NANO))
			ntp_timex.constant += 4;
		if (ntp_timex.constant > MAXTIMECONST)
			ntp_timex.constant = MAXTIMECONST;
		if (ntp_timex.constant < 0)
			ntp_timex.constant = 0;
	}
	if (buf->modes & ADJ_TICK) {
		if (buf->tick > MAX_TICK(base_tick) || buf->tick < MIN_TICK(base_tick)) {
			r = -1;
		} else
			ntp_timex.tick = buf->tick;
	}
	if ((buf->modes & ADJ_OFFSET_SINGLESHOT) != ADJ_OFFSET_SINGLESHOT) {
		if (buf->modes & ADJ_OFFSET) {
			update_ntp_offset(buf->offset);
		}
	}
	if (buf->modes & ADJ_SETOFFSET) {
		if (ntp_timex.status & STA_NANO)
			time += buf->time.tv_sec + buf->time.tv_usec * 1e-9;
		else
			time += buf->time.tv_sec + buf->time.tv_usec * 1e-6;
		ntp_timex.maxerror = MAXMAXERROR;
	}
	if (buf->modes & ADJ_TAI) {
		ntp_timex.tai = buf->constant;
	}

	t = ntp_timex;
	t.modes = buf->modes;

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
	generate = false;
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

void Refclock::set_generation(bool enable) {
	generate = enable;
}

void Refclock::update(double time, const Clock *clock) {
	if (!generate || !offset_generator)
		return;

	this->time = clock->get_real_time();
	offset = this->time - time + offset_generator->generate(NULL);
	valid = true;
}

bool Refclock::get_sample(double *time, double *offset) const {
	*time = this->time;
	*offset = this->offset;
	return valid;
}

void Refclock::get_offsets(double *offsets, int size) {
	int i;

	for (i = 0; i < size; i++)
		offsets[i] = offset_generator ? offset_generator->generate(NULL) : 0.0;
}
