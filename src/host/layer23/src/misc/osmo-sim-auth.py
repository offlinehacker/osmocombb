#!/usr/bin/python2.6

"""
Test script for (U)SIM authentication
Copyright (C) 2011 Harald Welte <laforge@gnumonks.org>

based heavily on the "card" library by Benoit Michau and pyscard

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
"""

from binascii import *
from card.utils import *
from optparse import OptionParser
from card.USIM import USIM
from card.SIM import SIM

def handle_usim(options, rand_bin, autn_bin, pin=None):
	u = USIM()
	if not u:
		print "Error opening USIM"
		exit(1)

	if options.debug:
		u.dbg = 2;

	imsi = u.get_imsi()
	print "Testing USIM card with IMSI %s" % imsi

	print "\nUMTS Authentication"
	ret = u.authenticate(rand_bin, autn_bin, ctx='3G')
	if len(ret) == 1:
		print "AUTS:\t%s" % b2a_hex(byteToString(ret[0]))
	else:
		print "RES:\t%s" % b2a_hex(byteToString(ret[0]))
		print "CK:\t%s" % b2a_hex(byteToString(ret[1]))
		print "IK:\t%s" % b2a_hex(byteToString(ret[2]))
		if len(ret) == 4:
			print "Kc:\t%s" % b2a_hex(byteToString(ret[3]))

	print "\nGSM Authentication"
	ret = u.authenticate(rand_bin, autn_bin, ctx='2G')
	if not len(ret) == 2:
		print "Error during 2G authentication"
		exit(1)
	print "SRES:\t%s" % b2a_hex(byteToString(ret[0]))
	print "Kc:\t%s" % b2a_hex(byteToString(ret[1]))

def handle_sim(options, rand_bin, pin=None):
	s= SIM()
	if not s:
		print "Error opening SIM"
		exit(1)

        if pin:
            s.verify_pin(pin)

	imsi = s.get_imsi()
	print "Testing SIM card with IMSI %s" % imsi

	print "\nGSM Authentication"
	ret = s.run_gsm_alg(rand_bin)
	print "SRES:\t%s" % b2a_hex(byteToString(ret[0]))
	print "Kc:\t%s" % b2a_hex(byteToString(ret[1]))


if __name__ == "__main__":
	parser = OptionParser()
	parser.add_option("-a", "--autn", dest="autn",
			  help="AUTN parameter from AuC")
	parser.add_option("-r", "--rand", dest="rand",
			  help="RAND parameter from AuC")
	parser.add_option("-d", "--debug", dest="debug",
			  help="Enable debug output",
			  action="store_true")
	parser.add_option("-s", "--sim", dest="sim",
			  help="SIM mode (default: USIM)",
			  action="store_true", default=False)
        parser.add_option("-p", "--pin", dest="pin",
                          help="PIN code to unlock")

	(options, args) = parser.parse_args()

	if not options.rand:
		print "You have to specify RAND"
		exit(2)

	rand_bin = stringToByte(a2b_hex(options.rand))
	if options.autn:
		autn_bin = stringToByte(a2b_hex(options.autn))

	if options.sim == True:
		handle_sim(options, rand_bin, options.pin)
	else:
		if not options.autn:
			print "You have to specify AUTN"
			exit(2)
		handle_usim(options, rand_bin, autn_bin, options.pin)

