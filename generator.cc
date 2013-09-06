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

#include "generator.h"

static void syntax_assert(bool condition) {
	if (!condition) {
		fprintf(stderr, "syntax error\n");
		exit(1);
	}
}

Generator::Generator(const vector<double> *parameters, const vector<Generator *> *input_generators) {
       	if (parameters)
		this->parameters = *parameters;
	if (input_generators)
		this->input_generators = *input_generators;
}


Generator::~Generator() {
	while (!input_generators.empty()) {
		delete input_generators.back();
		input_generators.pop_back();
	}
}

Generator_random_uniform::Generator_random_uniform(const vector<double> *parameters, const vector<Generator *> *input_generators): Generator(NULL, NULL) {
	syntax_assert(!parameters || parameters->size() == 0);
	syntax_assert(!input_generators || input_generators->size() == 0);
}

double Generator_random_uniform::generate() {
	double x;

	x = ((random() & 0x7fffffff) + 1) / 2147483649.0;
	x = ((random() & 0x7fffffff) + x) / 2147483648.0;

	return x;
}

Generator_random_normal::Generator_random_normal(const vector<double> *parameters, const vector<Generator *> *input_generators): Generator(NULL, NULL), uniform(NULL, NULL) {
	syntax_assert(!parameters || parameters->size() == 0);
	syntax_assert(!input_generators || input_generators->size() == 0);
}

double Generator_random_normal::generate() {
	/* Marsaglia polar method */

	double x, y, s;

	do {
		x = 2.0 * uniform.generate() - 1.0;
		y = 2.0 * uniform.generate() - 1.0;
		s = x * x + y * y;
	} while (s >= 1.0);

	x *= sqrt(-2.0 * log(s) / s);

	return x;
}

Generator_random_exponential::Generator_random_exponential(const vector<double> *parameters, const vector<Generator *> *input_generators): Generator(NULL, NULL), uniform(NULL, NULL) {
	syntax_assert(!parameters || parameters->size() == 0);
	syntax_assert(!input_generators || input_generators->size() == 0);
}

double Generator_random_exponential::generate() {
	return -log(uniform.generate());
}

Generator_random_poisson::Generator_random_poisson(const vector<double> *parameters, const vector<Generator *> *input_generators): Generator(NULL, NULL), uniform(NULL, NULL) {
	double lambda;

	syntax_assert(parameters && parameters->size() == 1);
	syntax_assert(!input_generators || input_generators->size() == 0);

	lambda = (*parameters)[0];
	syntax_assert(lambda >= 1 && lambda <= 20);
	L = exp(-lambda);
}

double Generator_random_poisson::generate() {
	double p;
	int k;

	for (p = 1.0, k = 0; k < 100; k++) {
		p *= uniform.generate();
		if (p <= L)
			break;
	}

	return k;
}

Generator_file::Generator_file(const char *file): Generator(NULL, NULL) {
	input = fopen(file, "r");
	if (!input) {
		fprintf(stderr, "can't open %s\n", file);
		exit(1);
	}
}

Generator_file::~Generator_file() {
	fclose(input);
}

double Generator_file::generate() {
	double x;

	while (1) {
		if (fscanf(input, "%lf", &x) != 1) {
			if (feof(input)) {
				fseek(input, 0, SEEK_SET);
				continue;
			}
			assert(0);
		}
		break;
	}
	return x;
}

Generator_wave_pulse::Generator_wave_pulse(const vector<double> *parameters, const vector<Generator *> *input_generators): Generator(NULL, NULL) {
	syntax_assert(parameters && parameters->size() == 2);
	syntax_assert(!input_generators || input_generators->size() == 0);
	high = (*parameters)[0];
	low = (*parameters)[1];
	counter = 0;
}

double Generator_wave_pulse::generate() {
	counter++;
	if (counter > high + low)
		counter = 1;
	if (counter <= high)
		return 1.0;
	return -1.0;
}

Generator_wave_sine::Generator_wave_sine(const vector<double> *parameters, const vector<Generator *> *input_generators): Generator(NULL, NULL) {
	syntax_assert(parameters && parameters->size() == 1);
	syntax_assert(!input_generators || input_generators->size() == 0);
	length = (*parameters)[0];
	counter = 0;
}

double Generator_wave_sine::generate() {
	return sin(counter++ / length * 2 * M_PI);
}

Generator_wave_triangle::Generator_wave_triangle(const vector<double> *parameters, const vector<Generator *> *input_generators): Generator(NULL, NULL) {
	syntax_assert(parameters && parameters->size() == 1);
	syntax_assert(!input_generators || input_generators->size() == 0);
	length = (*parameters)[0];
	counter = 0;
}

double Generator_wave_triangle::generate() {
	double phase;
	phase = counter / length - floor(counter / length);
	counter++;
	return -4.0 * (fabs(phase - 0.5) - 0.25);

}

Generator_sum::Generator_sum(const vector<double> *parameters, const vector<Generator *> *input_generators): Generator(parameters, input_generators) {
	sum = 0.0;
}

double Generator_sum::generate() {
	unsigned int i;

	for (i = 0; i < parameters.size(); i++)
		sum += parameters[i];
	for (i = 0; i < input_generators.size(); i++)
		sum += input_generators[i]->generate();
	return sum;
}

Generator_multiply::Generator_multiply(const vector<double> *parameters, const vector<Generator *> *input_generators): Generator(parameters, input_generators) {
}

double Generator_multiply::generate() {
	unsigned int i;
	double x = 1.0;

	for (i = 0; i < parameters.size(); i++)
		x *= parameters[i];
	for (i = 0; i < input_generators.size(); i++)
		x *= input_generators[i]->generate();
	return x;
}

Generator_add::Generator_add(const vector<double> *parameters, const vector<Generator *> *input_generators): Generator(parameters, input_generators) {
}

double Generator_add::generate() {
	unsigned int i;
	double x = 0.0;

	for (i = 0; i < parameters.size(); i++)
		x += parameters[i];
	for (i = 0; i < input_generators.size(); i++)
		x += input_generators[i]->generate();
	return x;
}

Generator_equal::Generator_equal(const vector<double> *parameters, const vector<Generator *> *input_generators): Generator(parameters, input_generators) {
	syntax_assert(parameters && parameters->size() > 0);
}

double Generator_equal::generate() {
	unsigned int i, c = 0;
	double x, min = 0.0, max = 0.0, epsilon = parameters[0];

	for (i = 1; i < parameters.size(); i++, c++) {
		x = parameters[i];
		if (!c || min > x)
			min = x;
		if (!c || max < x)
			max = x;
	}

	for (i = 0; i < input_generators.size(); i++, c++) {
		x = input_generators[i]->generate();
		if (!c || min > x)
			min = x;
		if (!c || max < x)
			max = x;
	}

	return max - min <= epsilon ? 1.0 : 0.0;
}

Generator_max::Generator_max(const vector<double> *parameters, const vector<Generator *> *input_generators): Generator(parameters, input_generators) {
	syntax_assert((parameters && parameters->size() > 0) || (input_generators && input_generators->size() > 0));
}

double Generator_max::generate() {
	unsigned int i, c = 0;
	double x, max = 0.0;

	for (i = 0; i < parameters.size(); i++, c++) {
		x = parameters[i];
		if (!c || max < x)
			max = x;
	}

	for (i = 0; i < input_generators.size(); i++, c++) {
		x = input_generators[i]->generate();
		if (!c || max < x)
			max = x;
	}

	return max;
}

Generator_min::Generator_min(const vector<double> *parameters, const vector<Generator *> *input_generators): Generator(parameters, input_generators) {
	syntax_assert((parameters && parameters->size() > 0) || (input_generators && input_generators->size() > 0));
}

double Generator_min::generate() {
	unsigned int i, c = 0;
	double x, min = 0.0;

	for (i = 0; i < parameters.size(); i++, c++) {
		x = parameters[i];
		if (!c || min > x)
			min = x;
	}

	for (i = 0; i < input_generators.size(); i++, c++) {
		x = input_generators[i]->generate();
		if (!c || min > x)
			min = x;
	}

	return min;
}

Generator_generator::Generator_generator() {
}

Generator_generator::~Generator_generator() {
}

Generator *Generator_generator::generate(char *code) const {
	const char *ws = " \t\n\r", *wsp = " \t\n\r()";
	int len, paren;
	Generator *ret;
	vector<double> params;
	vector<Generator *> generators;
	char *arg, *name, *end, *string = NULL;

	//printf("code: |%s|\n", code);
	len = strlen(code);
	end = code + len;

	if (code[0] == '(') {
		syntax_assert(len > 2 && code[len - 1] == ')');
		code[len - 1] = '\0';
		code++;
		end = code + len - 2;
	}

	code += strspn(code, ws);
	
	name = code;

	code += strcspn(code, wsp);
	code[0] = '\0';
	code++;

	code += strspn(code, ws);

	while (code < end) {
		arg = code;

		if (arg[0] == '(') {
			code = ++arg;
			for (paren = 1; code < end; code++) {
				if (code[0] == '(')
					paren++;
				else if (code[0] == ')')
					paren--;
				if (paren == 0)
					break;
			}

			syntax_assert(paren == 0 && code[0] == ')');
			code[0] = '\0';
			code++;

			//printf("generator: %s\n", arg);
			generators.push_back(generate(arg));
			syntax_assert(generators.back());
		} else if (arg[0] == '"') {
			string = code = ++arg;
			code += strcspn(code, "\"");
			syntax_assert(code[0] == '"');
			code[0] = '\0';
			code++;
			//printf("string: |%s|\n", string);
		} else {
			code += strcspn(code, wsp);
			syntax_assert(code[0] != ')' && code[0] != '(');
			code[0] = '\0';
			code++;
			params.push_back(atof(arg));
			//printf("param: %f\n", params.back());
		}

		code += strspn(code, ws);
	}

	if (strcmp(name, "*") == 0)
		ret = new Generator_multiply(&params, &generators);
	else if (strcmp(name, "+") == 0)
		ret = new Generator_add(&params, &generators);
	else if (strcmp(name, "sum") == 0)
		ret = new Generator_sum(&params, &generators);
	else if (strcmp(name, "uniform") == 0)
		ret = new Generator_random_uniform(&params, &generators);
	else if (strcmp(name, "normal") == 0)
		ret = new Generator_random_normal(&params, &generators);
	else if (strcmp(name, "exponential") == 0)
		ret = new Generator_random_exponential(&params, &generators);
	else if (strcmp(name, "poisson") == 0)
		ret = new Generator_random_poisson(&params, &generators);
	else if (strcmp(name, "file") == 0)
		ret = new Generator_file(string);
	else if (strcmp(name, "pulse") == 0)
		ret = new Generator_wave_pulse(&params, &generators);
	else if (strcmp(name, "sine") == 0)
		ret = new Generator_wave_sine(&params, &generators);
	else if (strcmp(name, "triangle") == 0)
		ret = new Generator_wave_triangle(&params, &generators);
	else if (strcmp(name, "equal") == 0)
		ret = new Generator_equal(&params, &generators);
	else if (strcmp(name, "max") == 0)
		ret = new Generator_max(&params, &generators);
	else if (strcmp(name, "min") == 0)
		ret = new Generator_min(&params, &generators);
	else {
		ret = NULL;
		syntax_assert(0);
	}

	return ret;
}
