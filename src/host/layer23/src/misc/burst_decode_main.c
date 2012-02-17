/* Main method of the layer2/3 stack */

/* (C) 2010 by Holger Hans Peter Freyther
 * (C) 2010 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <osmocom/bb/common/osmocom_data.h>
#include <osmocom/bb/common/l1ctl.h>
#include <osmocom/bb/common/l1l2_interface.h>
#include <osmocom/bb/common/sap_interface.h>
#include <osmocom/bb/misc/layer3.h>
#include <osmocom/bb/common/logging.h>
#include <osmocom/bb/common/l23_app.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/gsmtap_util.h>
#include <osmocom/core/gsmtap.h>
#include <osmocom/core/utils.h>

#include <arpa/inet.h>

#define _GNU_SOURCE
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>

struct log_target *stderr_target;

static char *gsmtap_ip = NULL;

void *l23_ctx= NULL;

int (*l23_app_work) (struct osmocom_ms *ms) = NULL;
int (*l23_app_exit) (struct osmocom_ms *ms) = NULL;
struct gsmtap_inst *gsmtap_inst;

const char *openbsc_copyright =
	"%s"
	"%s\n"
	"License GPLv2+: GNU GPL version 2 or later "
		"<http://gnu.org/licenses/gpl.html>\n"
	"This is free software: you are free to change and redistribute it.\n"
	"There is NO WARRANTY, to the extent permitted by law.\n\n";

static void print_usage(const char *app)
{
	printf("Usage: %s\n", app);
}

static void print_help()
{
	int options = 0xff;
	struct l23_app_info *app = l23_app_info();

	if (app && app->cfg_supported != 0)
		options = app->cfg_supported();

	printf(" Some help...\n");
	printf("  -h --help		this text\n");

	if (options & L23_OPT_TAP)
		printf("  -i --gsmtap-ip	The destination IP used for GSMTAP.\n");

	if (app && app->cfg_print_help)
		app->cfg_print_help();
}

static void build_config(char **opt, struct option **option)
{
	struct l23_app_info *app;
	struct option *app_opp = NULL;
	int app_len = 0, len;

	static struct option long_options[] = {
		{"help", 0, 0, 'h'},
		{"gsmtap-ip", 1, 0, 'i'},
		{"debug", 1, 0, 'd'},
	};


	app = l23_app_info();
	*opt = talloc_asprintf(l23_ctx, "hs:S:a:i:v:d:%s",
			       app && app->getopt_string ? app->getopt_string : "");

	len = ARRAY_SIZE(long_options);
	if (app && app->cfg_getopt_opt)
		app_len = app->cfg_getopt_opt(&app_opp);

	*option = talloc_zero_array(l23_ctx, struct option, len + app_len + 1);
	memcpy(*option, long_options, sizeof(long_options));
	memcpy(*option + len, app_opp, app_len * sizeof(struct option));
}

static void handle_options(int argc, char **argv)
{
	struct l23_app_info *app = l23_app_info();
	struct option *long_options;
	char *opt;

	build_config(&opt, &long_options);

	while (1) {
		int option_index = 0, c;

		c = getopt_long(argc, argv, opt,
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_usage(argv[0]);
			print_help();
			exit(0);
			break;
		case 'i':
			gsmtap_ip = optarg;
			break;
		default:
			if (app && app->cfg_handle_opt)
				app->cfg_handle_opt(c, optarg);
			break;
		}
	}

	talloc_free(opt);
	talloc_free(long_options);
}

static void print_copyright()
{
	struct l23_app_info *app;
	app = l23_app_info();
	printf(openbsc_copyright,
	       app && app->copyright ? app->copyright : "",
	       app && app->contribution ? app->contribution : "");
}

int main(int argc, char **argv)
{
	int rc;

	log_init(&log_info, NULL);
	stderr_target = log_target_create_stderr();
	log_add_target(stderr_target);
	log_set_all_filter(stderr_target, 1);

	//print_copyright();

    l23_app_in();
	handle_options(argc, argv);

	if (gsmtap_ip) {
		gsmtap_inst = gsmtap_source_init(gsmtap_ip, GSMTAP_UDP_PORT, 1);
		if (!gsmtap_inst) {
			fprintf(stderr, "Failed during gsmtap_init()\n");
			exit(1);
		}
		gsmtap_source_add_sink(gsmtap_inst);
	}

    l23_app_wo();

	return 0;
}
