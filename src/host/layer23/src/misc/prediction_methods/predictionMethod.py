class PredictionMethod(object):
    def splitCount(self, s, count):
         return [''.join(x) for x in zip(*[list(s[z::count]) for z in range(count)])]

    def _alterByte(self, data, offset, byte):
        t= self.splitCount(data,2)
        t[offset]= "%02x" % (int(t[offset],16)+byte)
        return "".join(t)

    def Predict(self, frames, args):
        pass

    def __init__(self, name, group):
        self.name= name
        self.group= group
