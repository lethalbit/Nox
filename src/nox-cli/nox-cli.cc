// SPDX-License-Identifier: GPL-3.0-or-later
/* nox-cli.cc - Nox CLI main entrypoint */
#include <config.hh>

#include <substrate/utility>
#include <substrate/console>
#include <substrate/conversions>


#include <string_view>
#include <string>
#include <vector>
#include <cerrno>
#include <cstring>

#include <cstdint>
#include <getopt.h>
#include <unistd.h>

namespace noxcfg = Nox::compiletime;

static struct option lopts[] = {
	{ "help",    no_argument,       0, 'h' },
	{ "version", no_argument,       0, 'v' },
	{ "debug",   no_argument,       0, 'd' },
	{ 0, 0, 0, 0 }
};

void print_banner();
void print_help();
void print_version();


int main(int argc, char** argv) {
	substrate::console = {stdout, stderr};
	substrate::console.showDebug(false);

	int o;
	int opt_idx{0};
	while((o = getopt_long(argc, argv, "hvd", lopts, &opt_idx)) != -1) {
		switch(o) {
			 case 'h': {
				print_help();
				exit(1);
			} case 'v': {
				print_version();
				exit(1);
			} case 'd': {
				substrate::console.showDebug(true);
				break;
			} case '?': {
				exit(1);
			} default: {
				exit(1);
			}

		}
	}

	print_banner();

	return {};
}


void print_banner() {
	substrate::console.writeln(
		"nox-cli v"sv, noxcfg::version
		," "sv,        noxcfg::git_hash
		," ("sv,       noxcfg::compiler
		," "sv,        noxcfg::compiler_version
		," "sv,        noxcfg::target_system
		,"-"sv,        noxcfg::target_arch
		,")"sv
	);

	substrate::console.writeln("Tanuki is licensed under the GNU GPL version 3 or later <https://www.gnu.org/licenses/gpl>"sv);
}

void print_help() {
	print_banner();

	substrate::console.writeln("Usage:"sv);
	substrate::console.writeln("\n\tnox-cli [options] [-s <script>]...\n"sv);
	substrate::console.writeln("  --help,    -h       Print this help text and exit"sv);
	substrate::console.writeln("  --version, -v       Print version and exit"sv);
	substrate::console.writeln("  --debug,   -d       Prints debug output THIS WILL GENERATE A LOT OF MESSAGGES"sv);

	substrate::console.writeln("\nPlease report bugs at <"sv, noxcfg::bugreport_url, ">"sv);
}

void print_version() {
	substrate::console.writeln("nox-cli v"sv, noxcfg::version, " "sv, noxcfg::git_hash);
}
