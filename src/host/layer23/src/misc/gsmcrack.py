import telnetlib

from lxml import etree
from lxml import objectify
from io import FileIO

class gsmcrack(object):
    def FindEncriptedBurstsAndErrorRate( self ):
        pass

    def DecriptData( self, PredictFile ):
        pass

    def __init__( self, filename, kraken_ip, kraken_port ):
        self.data= objectify.parse(FileIO(filename))
        self.kraken_ip= kraken_ip
        self.kraken_port= kraken_port

if __name__ == "__main__":
    a=1
