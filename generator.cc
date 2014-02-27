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

Generator::Generator(const vector<Generator *> *input) {
	if (input)
		this->input = *input;
	constant = false;
}

Generator::~Generator() {
	while (!input.empty()) {
		delete input.back();
		input.pop_back();
	}
}

bool Generator::is_constant() const {
	return constant;
}

Generator_float::Generator_float(double f): Generator(NULL) {
	this->f = f;
	constant = true;
}

double Generator_float::generate(const Generator_variables *variables) {
	return f;
}

Generator_variable::Generator_variable(string name): Generator(NULL) {
	this->name = name;
}

double Generator_variable::generate(const Generator_variables *variables) {
	Generator_variables::const_iterator iter;

	syntax_assert(variables);
	iter = variables->find(name);
	syntax_assert(iter != variables->end());

	return iter->second;
}

Generator_random_uniform::Generator_random_uniform(const vector<Generator *> *input):
	Generator(NULL) {
	syntax_assert(!input || input->size() == 0);
}

double Generator_random_uniform::generate(const Generator_variables *variables) {
	double x;

	x = ((random() & 0x7fffffff) + 1) / 2147483649.0;
	x = ((random() & 0x7fffffff) + x) / 2147483648.0;

	return x;
}

Generator_random_normal::Generator_random_normal(const vector<Generator *> *input):
	Generator(NULL), uniform(NULL) {
	syntax_assert(!input || input->size() == 0);
}

double Generator_random_normal::generate(const Generator_variables *variables) {
	/* Marsaglia polar method */

	double x, y, s;

	do {
		x = 2.0 * uniform.generate(variables) - 1.0;
		y = 2.0 * uniform.generate(variables) - 1.0;
		s = x * x + y * y;
	} while (s >= 1.0);

	x *= sqrt(-2.0 * log(s) / s);

	return x;
}

Generator_random_exponential::Generator_random_exponential(const vector<Generator *> *input):
	Generator(NULL), uniform(NULL) {
	syntax_assert(!input || input->size() == 0);
}

double Generator_random_exponential::generate(const Generator_variables *variables) {
	return -log(uniform.generate(variables));
}

Generator_random_poisson::Generator_random_poisson(const vector<Generator *> *input):
	Generator(NULL), uniform(NULL) {
	double lambda;

	syntax_assert(input && input->size() == 1 && (*input)[0]->is_constant());

	lambda = (*input)[0]->generate(NULL);
	syntax_assert(lambda >= 1 && lambda <= 20);
	L = exp(-lambda);
}

double Generator_random_poisson::generate(const Generator_variables *variables) {
	double p;
	int k;

	for (p = 1.0, k = 0; k < 100; k++) {
		p *= uniform.generate(variables);
		if (p <= L)
			break;
	}

	return k;
}

Generator_file::Generator_file(const char *file): Generator(NULL) {
	input = fopen(file, "r");
	if (!input) {
		fprintf(stderr, "can't open %s\n", file);
		exit(1);
	}
}

Generator_file::~Generator_file() {
	fclose(input);
}

double Generator_file::generate(const Generator_variables *variables) {
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

Generator_wave_pulse::Generator_wave_pulse(const vector<Generator *> *input):
	Generator(NULL) {
	syntax_assert(input && input->size() == 2 &&
			(*input)[0]->is_constant() && (*input)[1]->is_constant());
	high = (*input)[0]->generate(NULL);
	low = (*input)[1]->generate(NULL);
	counter = 0;
}

double Generator_wave_pulse::generate(const Generator_variables *variables) {
	counter++;
	if (counter > high + low)
		counter = 1;
	if (counter <= high)
		return 1.0;
	return -1.0;
}

Generator_wave_sine::Generator_wave_sine(const vector<Generator *> *input):
	Generator(NULL) {
	syntax_assert(input && input->size() == 1 && (*input)[0]->is_constant());
	length = (*input)[0]->generate(NULL);
	counter = 0;
}

double Generator_wave_sine::generate(const Generator_variables *variables) {
	return sin(counter++ / length * 2 * M_PI);
}

Generator_wave_cosine::Generator_wave_cosine(const vector<Generator *> *input):
	Generator(NULL) {
	syntax_assert(input && input->size() == 1 && (*input)[0]->is_constant());
	length = (*input)[0]->generate(NULL);
	counter = 0;
}

double Generator_wave_cosine::generate(const Generator_variables *variables) {
	return cos(counter++ / length * 2 * M_PI);
}

Generator_wave_triangle::Generator_wave_triangle(const vector<Generator *> *input):
	Generator(NULL) {
	syntax_assert(input && input->size() == 1 && (*input)[0]->is_constant());
	length = (*input)[0]->generate(NULL);
	counter = 0;
}

double Generator_wave_triangle::generate(const Generator_variables *variables) {
	double phase;
	phase = counter / length - floor(counter / length);
	counter++;
	return -4.0 * (fabs(phase - 0.5) - 0.25);

}

Generator_sum::Generator_sum(const vector<Generator *> *input):
	Generator(input) {
	sum = 0.0;
}

double Generator_sum::generate(const Generator_variables *variables) {
	unsigned int i;

	for (i = 0; i < input.size(); i++)
		sum += input[i]->generate(variables);
	return sum;
}

Generator_multiply::Generator_multiply(const vector<Generator *> *input):
	Generator(input) {
}

double Generator_multiply::generate(const Generator_variables *variables) {
	unsigned int i;
	double x = 1.0;

	for (i = 0; i < input.size(); i++)
		x *= input[i]->generate(variables);
	return x;
}

Generator_add::Generator_add(const vector<Generator *> *input):
	Generator(input) {
}

double Generator_add::generate(const Generator_variables *variables) {
	unsigned int i;
	double x = 0.0;

	for (i = 0; i < input.size(); i++)
		x += input[i]->generate(variables);
	return x;
}

Generator_modulo::Generator_modulo(const vector<Generator *> *input):
	Generator(input) {
	syntax_assert(input && input->size() > 0);
}

double Generator_modulo::generate(const Generator_variables *variables) {
	unsigned int i;
	double x = input[0]->generate(variables);

	for (i = 1; i < input.size(); i++)
		x = fmod(x, input[i]->generate(variables));

	return x;
}

Generator_equal::Generator_equal(const vector<Generator *> *input):
	Generator(input) {
	syntax_assert(input && input->size() > 0);
}

double Generator_equal::generate(const Generator_variables *variables) {
	unsigned int i;
	double x, min = 0.0, max = 0.0, epsilon = input[0]->generate(variables);

	for (i = 1; i < input.size(); i++) {
		x = input[i]->generate(variables);
		if (i == 1 || min > x)
			min = x;
		if (i == 1 || max < x)
			max = x;
	}

	return max - min <= epsilon ? 1.0 : 0.0;
}

Generator_max::Generator_max(const vector<Generator *> *input):
	Generator(input) {
	syntax_assert(input && input->size() > 0);
}

double Generator_max::generate(const Generator_variables *variables) {
	unsigned int i;
	double x, max = 0.0;

	for (i = 0; i < input.size(); i++) {
		x = input[i]->generate(variables);
		if (!i || max < x)
			max = x;
	}

	return max;
}

Generator_min::Generator_min(const vector<Generator *> *input):
	Generator(input) {
	syntax_assert(input && input->size() > 0);
}

double Generator_min::generate(const Generator_variables *variables) {
	unsigned int i;
	double x, min = 0.0;

	for (i = 0; i < input.size(); i++) {
		x = input[i]->generate(variables);
		if (!i || min > x)
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
			if (isalpha(arg[0])) {
				generators.push_back(new Generator_variable(arg));
				//printf("variable: %s\n", arg);
			} else {
				generators.push_back(new Generator_float(atof(arg)));
				//printf("float: %f\n", generators.back()->generate());
			}
		}

		code += strspn(code, ws);
	}

	if (strcmp(name, "*") == 0)
		ret = new Generator_multiply(&generators);
	else if (strcmp(name, "+") == 0)
		ret = new Generator_add(&generators);
	else if (strcmp(name, "%") == 0)
		ret = new Generator_modulo(&generators);
	else if (strcmp(name, "sum") == 0)
		ret = new Generator_sum(&generators);
	else if (strcmp(name, "uniform") == 0)
		ret = new Generator_random_uniform(&generators);
	else if (strcmp(name, "normal") == 0)
		ret = new Generator_random_normal(&generators);
	else if (strcmp(name, "exponential") == 0)
		ret = new Generator_random_exponential(&generators);
	else if (strcmp(name, "poisson") == 0)
		ret = new Generator_random_poisson(&generators);
	else if (strcmp(name, "file") == 0)
		ret = new Generator_file(string);
	else if (strcmp(name, "pulse") == 0)
		ret = new Generator_wave_pulse(&generators);
	else if (strcmp(name, "sine") == 0)
		ret = new Generator_wave_sine(&generators);
	else if (strcmp(name, "cosine") == 0)
		ret = new Generator_wave_cosine(&generators);
	else if (strcmp(name, "triangle") == 0)
		ret = new Generator_wave_triangle(&generators);
	else if (strcmp(name, "equal") == 0)
		ret = new Generator_equal(&generators);
	else if (strcmp(name, "max") == 0)
		ret = new Generator_max(&generators);
	else if (strcmp(name, "min") == 0)
		ret = new Generator_min(&generators);
	else {
		ret = NULL;
		syntax_assert(0);
	}

	return ret;
}
