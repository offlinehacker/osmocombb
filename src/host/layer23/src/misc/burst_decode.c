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
    int burst_count;

	sbit_t			bursts_dl[116 * 4];
	sbit_t			bursts_ul[116 * 4];

	uint8_t			kc[8];
    uint8_t         snr;
    int         ul;
    uint32_t    start_fn;
} app_state;

static void
burst_decipher(ubit_t *p_burst, ubit_t *c_burst, uint32_t fn)
{
    int i;

    ubit_t ks_dl[114], ks_ul[114], *ks = app_state.ul ? ks_ul : ks_dl;
    osmo_a5(1, app_state.kc, fn, ks_dl, ks_ul);
	for (i= 0; i< 114; i++)
        p_burst[i] = c_burst[i]^ks[i];
}

static sbit_t*
bursts_decode()
{
    int i, j;
    sbit_t bursts[116 * 4];

    printf("Decoding burst...\n");

    for(i=0; i<app_state.burst_count; i++)
        if (app_state.dch_ciph)
            burst_decipher(app_state.raw_bursts[i], app_state.raw_bursts[i], app_state.start_fn+i);

    for(j=0; j<app_state.burst_count; j++){
	    /* Convert to softbits */
	    for (i=0; i<57; i++)
		    bursts[(116*j)+i] = app_state.raw_bursts[j][i] ? - (app_state.snr >> 1) : (app_state.snr >> 1);
        bursts[(116*j)+57]= - (app_state.snr >> 1);
        bursts[(116*j)+58]= - (app_state.snr >> 1);
        for (i=59; i<116; i++)
            bursts[(116*j)+i] = app_state.raw_bursts[j][i-2] ? - (app_state.snr >> 1) : (app_state.snr >> 1);
    }

		uint8_t l2[23];
		int rv;
		rv = xcch_decode(l2, bursts);

		if (rv == 0)
		{
			uint8_t chan_type, chan_ts, chan_ss;
			uint8_t gsmtap_chan_type;

            printf( "RAW DATA: ");
            for  (i=0; i<23; i++)
                printf( "%x ", l2[i]);
            printf( "\n");

			/* Send to GSMTAP */
			gsmtap_send(gsmtap_inst,
				0, 0, 0, 0,
				ntohl(app_state.start_fn), 0, app_state.snr,
				l2, sizeof(l2)
			);
		}
		else
			LOGP(DRR, LOGL_NOTICE, "Error decoding data, data encripted?\n");
}

static int l23_getopt_options(struct option **options)
{
	static struct option opts [] = {
		{"kc", 1, 0, 'k'},
        {"burst", 1, 0, 'b'},
        {"snr", 1, 0, 's'},
        {"fn", 1, 0, 'f'},
        {"ul", 1, 0 ,'u'}
	};

	*options = opts;
	return ARRAY_SIZE(opts);
}

static int l23_cfg_print_help()
{
	printf("\nApplication specific\n");
	printf("  -k --kc KEY Key to use to try to decipher\n");
    printf("  -b --burst BURST Burst we want to decipher if kc is provided and decode if count is more than one\n");
    printf("  -s --snr SNR Signal to noise ration");
    printf("  -f --fn FN Frame number for first burst");
    printf("  -u --ul UL Uplink or downlink");

	return 0;
}

static int l23_cfg_handle(int c, const char *optarg)
{
    int x;

	switch (c) {
	case 'k':
		if (osmo_hexparse(optarg, app_state.kc, 8) != 8) {
			fprintf(stderr, "Invalid Kc\n");
			exit(-1);
		}

        app_state.dch_ciph= 1;
		break;
    case 'b':
        printf("BURST:%s, LEN; %d, COUNT:%d\n",optarg, strlen(optarg), app_state.burst_count);
        for(x=0;x<strlen(optarg);x++){
            if (optarg[x]==49)
                app_state.raw_bursts[app_state.burst_count][x]=1;
            else
                app_state.raw_bursts[app_state.burst_count][x]=0;
        }
        app_state.burst_count+= 1;
        break;
    case 's':
        app_state.snr= atoi(optarg);
        break;
    case 'f':
        app_state.start_fn=  atoi(optarg);
        break;
    case 'u':
        app_state.ul= 1;
	default:
		return -1;
	}
	return 0;
}

static void print_burst( ubit_t *burst )
{
    int x;

    for (x=0;x<114;x++)
        printf("%d", burst[x]);
    printf("\n");
}

int l23_app_wo()
{
    int x;
    sbit_t bursts[MAX_BURST_COUNT][114];

    if(app_state.burst_count>=4)
        bursts_decode();
    for(x=0;x<app_state.burst_count;x++)
        burst_decipher(bursts[x], app_state.raw_bursts[x], app_state.start_fn+x);

    printf("Decipherd data\n");
    if (app_state.burst_count>=4) {
        for(x=0;x<app_state.burst_count;x++)
            print_burst(app_state.raw_bursts[x]);
    }
    else{
        for(x=0;x<app_state.burst_count;x++)
            print_burst(bursts[x]);
    }

    return 1;
}

int l23_app_in()
{
    app_state.burst_count= 0;
    app_state.snr= 60;
    app_state.dch_ciph= 0;
    app_state.ul= 0;

    return 1;
}

static struct l23_app_info info = {
	.copyright	= "Copyright (C) 2010 Harald Welte <laforge@gnumonks.org>\n",
	.contribution	= "Contributions by Jaka Hudoklin\n",
	.getopt_string	= "k:b:s:f:u:",
	.cfg_getopt_opt = l23_getopt_options,
	.cfg_handle_opt	= l23_cfg_handle,
	.cfg_print_help	= l23_cfg_print_help,
};

struct l23_app_info *l23_app_info()
{
	return &info;
}
