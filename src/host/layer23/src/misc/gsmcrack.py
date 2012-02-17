import telnetlib

from lxml import etree
from lxml import objectify
from io import FileIO

class gsmcrack(object):
    def FindEncriptedBurstsAndErrorRate( self ):
        pass

    def DecriptData( self, PredictFile ):
        pass

    def RunKraken( self, keystream ):
        tn= telnetlib.Telnet(self.kraken_ip, self.kraken_port)
        tn.write("crack %s\r\n" % keystream)

        id= 0
        result=[]
        while 1:
            (index, match, text)= tn.expect([
                       'Found\s+([0-9abcdef]+)\s+@\s+([0-9]+)\s+#([0-9]+)',
                       'crack\s+#([0-9]+)\s+took\s+([0-9]+)\s+msec',
                       'Cracking\s+#([0-9]+)\s+([01]+)',
                      ], 400)
            if index==2 and match.group(2) in keystream:
                id=match.group(1)
                print "Crack id is:", id
            elif index==1:
                if match.group(1)==id:
                    print "End of crack:", id
                    break
            elif index==0:
                if match.group(3)==id:
                    print "New result for crack:", id, match.group(1), match.group(2)
                    result.append((match.group(1),match.group(2),))

        return result

    def __init__( self, filename, kraken_ip, kraken_port ):
        #self.data= objectify.parse(FileIO(filename))
        self.kraken_ip= kraken_ip
        self.kraken_port= kraken_port

if __name__ == "__main__":
    a=1
