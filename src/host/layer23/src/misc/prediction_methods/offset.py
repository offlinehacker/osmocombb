from predictionMethod import PredictionMethod

class offset(PredictionMethod):
    def Predict(self, frames, args):

        if "offset" not in args:
            return (None, None)

        cframe= frames.xpath("/scan/frame[@cipher='1']")[args["offset"]]
        print "Start of cipher is at frame", frames.xpath("/scan/frame[@cipher='1']")[0].xpath("burst")[-1].attrib["fn"]
        if not cframe:
            return (None,None)

        if "prediction" not in args:
            return (None,None)

        return (args["prediction"], cframe)

    def __init__(self):
        PredictionMethod.__init__(self, "offset", "all")
