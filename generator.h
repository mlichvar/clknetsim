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

#ifndef GENERATOR_H
#define GENERATOR_H

#include "sysheaders.h"
#include <vector>

using namespace std;

class Generator {
	protected:
	vector<double> parameters;
	vector<Generator *> input_generators;

	public:
	Generator(const vector<double> *parameters, const vector<Generator *> *input_generators);
	virtual ~Generator();
	virtual double generate() = 0;
};

class Generator_random_uniform: public Generator {
	public:
	Generator_random_uniform(const vector<double> *parameters, const vector<Generator *> *input_generators);
	virtual double generate();
};

class Generator_random_normal: public Generator {
	Generator_random_uniform uniform;

	public:
	Generator_random_normal(const vector<double> *parameters, const vector<Generator *> *input_generators);
	virtual double generate();
};

class Generator_random_exponential: public Generator {
	Generator_random_uniform uniform;

	public:
	Generator_random_exponential(const vector<double> *parameters, const vector<Generator *> *input_generators);
	virtual double generate();
};

class Generator_random_poisson: public Generator {
	Generator_random_uniform uniform;
	double L;

	public:
	Generator_random_poisson(const vector<double> *parameters, const vector<Generator *> *input_generators);
	virtual double generate();
};

class Generator_file: public Generator {
	FILE *input;

	public:
	Generator_file(const char *file);
	virtual ~Generator_file();
	virtual double generate();
};

class Generator_wave_pulse: public Generator {
	int high;
	int low;
	int counter;

	public:
	Generator_wave_pulse(const vector<double> *parameters, const vector<Generator *> *input_generators);
	virtual double generate();
};

class Generator_wave_sine: public Generator {
	double length;
	int counter;

	public:
	Generator_wave_sine(const vector<double> *parameters, const vector<Generator *> *input_generators);
	virtual double generate();
};

class Generator_wave_triangle: public Generator {
	double length;
	int counter;

	public:
	Generator_wave_triangle(const vector<double> *parameters, const vector<Generator *> *input_generators);
	virtual double generate();
};

class Generator_sum: public Generator {
	double sum;
	public:
	Generator_sum(const vector<double> *parameters, const vector<Generator *> *input_generators);
	virtual double generate();
};

class Generator_multiply: public Generator {
	public:
	Generator_multiply(const vector<double> *parameters, const vector<Generator *> *input_generators);
	virtual double generate();
};

class Generator_add: public Generator {
	public:
	Generator_add(const vector<double> *parameters, const vector<Generator *> *input_generators);
	virtual double generate();
};

class Generator_generator {
	public:
	Generator_generator();
	~Generator_generator();
	Generator *generate(char *code) const;
};

#endif
