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

bool load_config(const char *file, Network *network, unsigned int nodes) {
	Generator_generator generator;
	FILE *f;
	const char *ws = " \t\n\r";
	char line[1000], *var, *arg, *end;
	unsigned int node, node2;

	f = fopen(file, "r");
	if (!f)
		return false;

	while (fgets(line, sizeof (line), f)) {
		end = line + strlen(line);
		var = line + strspn(line, ws);
		arg = line + strcspn(line, "=");
		*arg++ = '\0';

		if (var >= end || *var == '#')
			continue;

		if (arg >= end)
			return false;

		while (end > line && (end[-1] == '\r' || end[-1] == '\n' || end[-1] == '\t' || end[-1] == ' '))
			*--end = '\0';

		arg += strspn(arg, ws);

		if (strncmp(var, "node", 4))
			return false;

		var += 4;
		node = atoi(var) - 1;
		if (node >= nodes)
			continue;

		var += strcspn(var, "_") + 1;
		if (var >= end)
			return false;

		if (strncmp(var, "offset", 6) == 0)
			network->get_node(node)->get_clock()->set_time(atof(arg));
		else if (strncmp(var, "start", 5) == 0)
			network->get_node(node)->set_start_time(atof(arg));
		else if (strncmp(var, "freq", 4) == 0) {
			if (arg[0] == '(')
				network->get_node(node)->get_clock()->set_freq_generator(generator.generate(arg));
			else
				network->get_node(node)->get_clock()->set_freq(atof(arg));
		} else if (strncmp(var, "shift_pll", 9) == 0)
			network->get_node(node)->get_clock()->set_ntp_shift_pll(atoi(arg));
		else if (strncmp(var, "fll_mode2", 9) == 0)
			network->get_node(node)->get_clock()->set_ntp_flag(atoi(arg), CLOCK_NTP_FLL_MODE2);
		else if (strncmp(var, "pll_clamp", 9) == 0)
			network->get_node(node)->get_clock()->set_ntp_flag(atoi(arg), CLOCK_NTP_PLL_CLAMP);
		else if (strncmp(var, "delay", 5) == 0) {
			var += 5;
			node2 = atoi(var) - 1;
			if (node2 >= nodes)
				continue;
			network->set_link_delay_generator(node, node2, generator.generate(arg));
		} else if (strncmp(var, "refclock", 8) == 0)
			network->get_node(node)->get_refclock()->set_offset_generator(generator.generate(arg));
		else
			return false;
	}

	fclose(f);

	return true;
}

int main(int argc, char **argv) {
	int nodes, help = 0, verbosity = 2, noslew = 0;
	double limit = 10000.0, reset = 0.0;
	const char *offset_log = NULL, *freq_log = NULL, *packet_log = NULL, *config, *socket = "clknetsim.sock";

	int r, opt;
	Network *network;
	Generator_generator gen;

	while ((opt = getopt(argc, argv, "l:r:o:f:p:ns:v:h")) != -1) {
		switch (opt) {
			case 'l':
				limit = atof(optarg);
				break;
			case 'r':
				reset = atof(optarg);
				break;
			case 'o':
				offset_log = optarg;
				break;
			case 'f':
				freq_log = optarg;
				break;
			case 'p':
				packet_log = optarg;
				break;
			case 'n':
				noslew = 1;
				break;
			case 's':
				socket = optarg;
				break;
			case 'v':
				verbosity = atoi(optarg);
				break;
			case 'h':
			default:
				help = 1;
		}
	}

	if (optind + 2 != argc || help) {
		printf("usage: clknetsim [options] config nodes\n");
		printf("       -l secs       set time limit to secs (default 10000)\n");
		printf("       -r secs       reset stats after secs (default 0)\n");
		printf("       -o file       log time offsets to file\n");
		printf("       -f file       log frequency offsets to file\n");
		printf("       -p file       log packet delays to file\n");
		printf("       -n            omit clock slew in frequency log and stats\n");
		printf("       -s socket     set server socket name (default clknetsim.sock)\n");
		printf("       -v level      set verbosity level (default 2)\n");
		printf("       -h            print usage\n");
		return 1;
	}
	
	config = argv[optind];
	nodes = atoi(argv[optind + 1]);

	srandom(time(NULL));

	network = new Network(socket, nodes);
	
	if (!load_config(config, network, nodes)) {
		fprintf(stderr, "Couldn't parse config %s\n", config);
		return 1;
	}

	if (!network->prepare_clients())
		return 1;

	if (offset_log)
		network->open_offset_log(offset_log);
	if (freq_log)
		network->open_freq_log(freq_log);
	if (packet_log)
		network->open_packet_log(packet_log);
	if (noslew)
		network->report_freq_noslew(true);

	fprintf(stderr, "Running simulation...");

	if (reset) {
		r = network->run(reset);
		network->reset_stats();
	} else
		r = true;

	if (r)
		r = network->run(limit);

	if (r) {
		fprintf(stderr, "done\n\n");
		network->print_stats(verbosity);
	} else
		fprintf(stderr, "failed\n");

	delete network;

	return !r;
}
