/* CCCH passive sniffer */
/* (C) 2010-2011 by Holger Hans Peter Freyther
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

#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <getopt.h>

#include <arpa/inet.h>

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/rsl.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/gsm48_ie.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/core/signal.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/core/gsmtap_util.h>
#include <osmocom/core/bits.h>
#include <osmocom/gsm/a5.h>

#include <osmocom/bb/common/logging.h>
#include <osmocom/bb/misc/rslms.h>
#include <osmocom/bb/misc/layer3.h>
#include <osmocom/bb/common/osmocom_data.h>
#include <osmocom/bb/common/l1ctl.h>
#include <osmocom/bb/common/l23_app.h>

#include <l1ctl_proto.h>

#include <osmocom/bb/misc/xcch.h>

extern struct gsmtap_inst *gsmtap_inst;

#define MAX_BURST_COUNT 8

static struct {
	int			dch_ciph;

	ubit_t raw_bursts[MAX_BURST_COUNT][114];

	uint8_t data[23]
} app_state;

static void print_burst( ubit_t *burst )
{
    int x;

    printf("<burst>\n");
    for (x=0;x<114;x++)
        printf("%d", burst[x]);
    printf("\n</burst>\n");
}

static void
frame_encode()
{
    int i, j;
    sbit_t bursts[116 * 4];
    sbit_t raw_bursts[4][114];


    xcch_encode(raw_bursts, app_state.data);

    printf("<frame>\n");
    for(i=0;i<4;i++)
        print_burst(raw_bursts[i]);
    printf("\n</frame>");
}

static int l23_getopt_options(struct option **options)
{
	static struct option opts [] = {
		{"data", 1, 0, 'd'},
	};

	*options = opts;
	return ARRAY_SIZE(opts);
}

static int l23_cfg_print_help()
{
	printf("\nApplication specific\n");
	printf("  -d --data DATA Input data\n");

	return 0;
}

static int l23_cfg_handle(int c, const char *optarg)
{
    int x;

	switch (c) {
	case 'd':
		if (osmo_hexparse(optarg, app_state.data, 23) != 23) {
			fprintf(stderr, "Invalid burst data\n");
			exit(-1);
		}

        app_state.dch_ciph= 1;
		break;
	default:
		return -1;
	}
	return 0;
}

int l23_app_wo()
{
    frame_encode();

    return 1;
}

int l23_app_in()
{
    return 1;
}

static struct l23_app_info info = {
	.copyright	= "Copyright (C) 2010 Harald Welte <laforge@gnumonks.org>\n",
	.contribution	= "Contributions by Jaka Hudoklin\n",
	.getopt_string	= "d:",
	.cfg_getopt_opt = l23_getopt_options,
	.cfg_handle_opt	= l23_cfg_handle,
	.cfg_print_help	= l23_cfg_print_help,
};

struct l23_app_info *l23_app_info()
{
	return &info;
}
