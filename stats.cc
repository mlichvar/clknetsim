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

#include "stats.h"

#include "sysheaders.h"

Stats::Stats() {
	reset();
}

Stats::~Stats() {
}

void Stats::reset() {
	reset_clock_stats();

	packets_in_sum2 = 0.0;
	packets_out_sum2 = 0.0;
	packets_in = 0;
	packets_out = 0;
	packets_in_time_last = 0.0;
	packets_out_time_last = 0.0;
	packets_in_int_sum = 0.0;
	packets_out_int_sum = 0.0;
	packets_in_int_min = 0.0;
	packets_out_int_min = 0.0;

	wakeups_int_sum = 0;
	wakeups = 0;
}

void Stats::reset_clock_stats() {
	offset_sum2 = 0.0;
	offset_abs_sum = 0.0;
	offset_sum = 0.0;
	offset_abs_max = 0.0;
	freq_sum2 = 0.0;
	freq_abs_sum = 0.0;
	freq_sum = 0.0;
	freq_abs_max = 0.0;
	rawfreq_sum2 = 0.0;
	rawfreq_abs_sum = 0.0;
	rawfreq_sum = 0.0;
	rawfreq_abs_max = 0.0;
	samples = 0;
}

void Stats::update_clock_stats(double offset, double freq, double rawfreq) {
	offset_sum2 += offset * offset;
	offset_abs_sum += fabs(offset);
	offset_sum += offset;
	if (offset_abs_max < fabs(offset))
		offset_abs_max = fabs(offset);

	freq_sum2 += freq * freq;
	freq_abs_sum += fabs(freq);
	freq_sum += freq;
	if (freq_abs_max < fabs(freq))
		freq_abs_max = fabs(freq);

	rawfreq_sum2 += rawfreq * rawfreq;
	rawfreq_abs_sum += fabs(rawfreq);
	rawfreq_sum += rawfreq;
	if (rawfreq_abs_max < fabs(rawfreq))
		rawfreq_abs_max = fabs(rawfreq);

	samples++;
	wakeups_int_sum++;
}

void Stats::update_packet_stats(bool incoming, double time, double delay) {
	if (delay < 0.0)
		delay = 0.0;
	if (incoming) {
		packets_in++;
		packets_in_sum2 += delay * delay;
		if (packets_in >= 2) {
			packets_in_int_sum += time - packets_in_time_last;
			if (packets_in == 2 || packets_in_int_min > time - packets_in_time_last)
				packets_in_int_min = time - packets_in_time_last;
		}
		packets_in_time_last = time;
	} else {
		packets_out++;
		packets_out_sum2 += delay * delay;
		if (packets_out >= 2) {
			packets_out_int_sum += time - packets_out_time_last;
			if (packets_out == 2 || packets_out_int_min > time - packets_out_time_last)
				packets_out_int_min = time - packets_out_time_last;
		}
		packets_out_time_last = time;
	}
}

void Stats::update_wakeup_stats() {
	wakeups++;
}

void Stats::print(int verbosity) const {
	if (verbosity <= 0)
		return;
	if (verbosity <= 1) {
		printf("%e ", sqrt(offset_sum2 / samples));
		return;
	}

	printf("RMS offset:                            \t%e\n", sqrt(offset_sum2 / samples));
	printf("Maximum absolute offset:               \t%e\n", offset_abs_max);
	printf("Mean absolute offset:                  \t%e\n", offset_abs_sum / samples);
	printf("Mean offset:                           \t%e\n", offset_sum / samples);
	printf("RMS frequency:                         \t%e\n", sqrt(freq_sum2 / samples));
	printf("Maximum absolute frequency:            \t%e\n", freq_abs_max);
	printf("Mean absolute frequency:               \t%e\n", freq_abs_sum / samples);
	printf("Mean frequency:                        \t%e\n", freq_sum / samples);
	printf("RMS raw frequency:                     \t%e\n", sqrt(rawfreq_sum2 / samples));
	printf("Maximum absolute raw frequency:        \t%e\n", rawfreq_abs_max);
	printf("Mean absolute raw frequency:           \t%e\n", rawfreq_abs_sum / samples);
	printf("Mean raw frequency:                    \t%e\n", rawfreq_sum / samples);
	if (packets_in) {
		printf("RMS incoming packet delay:             \t%e\n", (double)sqrt(packets_in_sum2 / packets_in));
	} else {
		printf("RMS incoming packet delay:             \tinf\n");
	}
	if (packets_in >= 2) {
		printf("Mean incoming packet interval:         \t%e\n", packets_in_int_sum / (packets_in - 1));
		printf("Minimum incoming packet interval:      \t%e\n", packets_in_int_min);
	} else {
		printf("Mean incoming packet interval:         \tinf\n");
		printf("Minimum incoming packet interval:      \tinf\n");
	}
	if (packets_out) {
		printf("RMS outgoing packet delay:             \t%e\n", (double)sqrt(packets_out_sum2 / packets_out));
	} else {
		printf("RMS outgoing packet delay:             \tinf\n");
	}
	if (packets_out >= 2) {
		printf("Mean outgoing packet interval:         \t%e\n", packets_out_int_sum / (packets_out - 1));
		printf("Minimum outgoing packet interval:      \t%e\n", packets_out_int_min);
	} else {
		printf("Mean outgoing packet interval:         \tinf\n");
		printf("Minimum outgoing packet interval:      \tinf\n");
	}
	if (wakeups)
		printf("Mean wakeup interval:                  \t%e\n", (double)wakeups_int_sum / wakeups);
	else
		printf("Mean wakeup interval:                  \tinf\n");
}
