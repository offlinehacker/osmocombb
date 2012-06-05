from predictionMethod import PredictionMethod

class SysInfo(PredictionMethod):
    def Predict(self, frames, args):
        select= 0
        if "select" in args: 
            if args["select"]=="last":
                select=-1

        sys_info= frames.xpath("/scan/frame/system_information")[select].getparent()
        if "filter" in args:
            sys_info= frames.xpath("/scan/frame[system_information="+str(args["filter"])+"]")[select]
        if not sys_info:
            return (None,None)

        offset= 102
        if "offset" in args: offset=int(args["offset"])

        cfn= int(sys_info.xpath("burst")[-1].attrib["fn"])+int(offset)
        print("SysInfo ", sys_info.xpath("system_information")[0].text," is at frame",
                sys_info.xpath("burst")[-1].attrib["fn"], "with count", 
                len(frames.xpath("/scan/frame/system_information")))

        prediction_data= sys_info.xpath("data")[0].text.strip()
        if "data" in args: prediction_data= args["data"]

        #should we change timing advance
        if "ta" in args: 
            prediction_data= self._alterByte( prediction_data, 1, int(args["ta"]) )

        #should we change power level
        if "pl" in args: 
            prediction_data= self._alterByte( prediction_data, 0, int(args["pl"]) )

        cframe= frames.xpath("/scan/frame/burst[@fn="+str(cfn)+"]")[0].getparent()

        return (prediction_data, cframe)

    def __init__(self):
        PredictionMethod.__init__(self, "sysinfo", "all")
