import glob

from lxml import objectify
from io import FileIO
from predictionMethod import PredictionMethod

class optimizer(PredictionMethod):
    def _frameWithCipher(self, frames):
        x=0
        for frame in frames:
            if int(frame.attrib["cipher"])==1:
                return x
            x+=1

        return None

    def _compareFrames(self, f1, f2):
        f1= self._splitCount(f1.xpath("data")[0].text.strip(),2)
        f2= self._splitCount(f2.xpath("data")[0].text.strip(),2)

        count= len(filter(lambda x: (f1[x]!= "2b") and (f2[x]!="2b") 
            and (f1[x]==f2[x]), range(0,len(f1))))

        return count

    def _compareMultipleFrames(self, frames1, frames2):
        total=0
        lines=0
        for x in range(0,min(len(frames1),len(frames2))):
            cur=self._compareFrames(frames1[x], frames2[x])
            if cur>10:
                lines+=1
            total+=cur

        return total*lines

    def _frameWithPattern(self, frames, pattern):
        pattern= self._splitCount(pattern.strip(),2)

        y=0
        for frame in frames:
            ret= frame.xpath("data")
            if not ret:
                y+=1
                break
            frame= self._splitCount(ret[0].text.strip(),2)
            res= filter(lambda x: pattern[x]==u"xx" or 
                int(pattern[x],16)==int(frame[x],16), range(0, len(pattern)))
            if len(res) == len(pattern):
                print "Pattern", pattern, "found", frame
                return y
            y+=1

        print "Pattern", pattern, "not found"
        return None

    def Predict(self, frames, args):

        if "predictPattern" not in args:
            return (None, None)

        if "startPattern" not in args:
            return (None, None)

        skip=""
        if "skip_file" in args:
            print "We will skip", args["skip_file"]
            skip=args["skip_file"]

        if "files" not in args:
            return (None, None)

        frames= frames.xpath("frame")
        frame_start= self._frameWithPattern(frames, args["startPattern"])
        if frame_start==None:
            print "Can't find frame start"
            return (None,None)
        frame_end= self._frameWithCipher(frames)
        count= frame_end-frame_start
        filteredFrames= frames[frame_start:frame_end]

        best_score= 0
        best_frames=None
        best_frame_end= 0
        for learnedFile in glob.glob(args["files"]):
            if learnedFile==skip:
                print "Skipping file", skip
                continue
            
            learnedFrames= objectify.parse(FileIO(learnedFile)).xpath("frame")
            learned_frame_end= self._frameWithCipher(learnedFrames)
            if learned_frame_end==None:
                print "Can't find frame start"
                return (None,None)
            learnedFilteredFrames= learnedFrames[learned_frame_end-count:
                    learned_frame_end]

            score= self._compareMultipleFrames(filteredFrames, learnedFilteredFrames)
            if score>best_score:
                print "Current score is", score, "with file", learnedFile
                best_score= score
                best_frames= learnedFrames 
                best_frame_end= learned_frame_end

        predictionFrameOffset= self._frameWithPattern(best_frames, args["predictPattern"])
        if predictionFrameOffset==None:
            print "Can't find prediction frame"
            return (None,None)

        prediction= best_frames[predictionFrameOffset].xpath("data")[0].text.strip()

        return (prediction, frames[(predictionFrameOffset-best_frame_end)+frame_end])

    def __init__(self):
        PredictionMethod.__init__(self, "optimizer", "all")
