from libs.yara_struct_parser import YaraFileParser
from libs.write_yara import YaraWriter
from libs.htmlfilter import YLParser
from libs.custom_struct import YaraStruct

import glob
import os
import difflib
import jsbeautifier
import string
import random
import yara


class YaraLearner:
    """ Yara Learner for learning the HTML file """
    def __init__(self, folder, yarafile, yaraflag, patternname, condition, count=3):
        self.folder = folder
        self.yarafile = yarafile
        self.yaraflag = yaraflag
        self.patternname = patternname
        self.condition = condition
        self.count = count

    def action(self):
        yfp = YaraFileParser(self.yarafile, self.yaraflag)
        yfp.action()
        ystruct = yfp.ystrlist
        del yfp

        # filter the yaraname match yarastruct(ystruct)
        try:
            ystruct = list(filter(lambda x: x.rulename == self.patternname, ystruct))[0]
        except:  # if yara rule is not exist?
            ystruct = YaraStruct()
            ystruct.rulename = self.patternname
            ystruct.rulecond = "%s of them" % self.condition # as a default


        flist = glob.glob(os.path.join(self.folder, '*'))

        tmp = []

        mPoint = []  # ruleset point
        tPoint = {}  # temporary ruleset point

        # learn the html rule pattern
        for fname in flist:
            yp = YLParser()
            yp.initialize()
            yp.feed(open(fname, 'rb').read().decode())
            extract = yp.data
            del yp

            if len(tmp) != 0:
                # check the difference point of previous ruleset
                if len(tmp) != len(extract): # if some script or src address add?
                    pass
                else:
                    for i in range(0, len(extract)):
                        nvalue = jsbeautifier.beautify(extract[i]).splitlines()
                        pvalue = jsbeautifier.beautify(tmp[i]).splitlines()
                        diff = difflib.ndiff(nvalue, pvalue)
                        for ediff in diff:  # check the html change point
                            if ediff[0] != "-" and ediff[0] != "+" and ediff[0] != "?": # if not modified?
                                if len(ediff.strip()) > 5:  # prevent for short detection
                                    if ediff.strip() in tPoint.keys() and ediff.strip() not in mPoint and tPoint[ediff.strip()] > self.count:
                                            mPoint.append(ediff.strip())  # add to ruleset
                                    else:
                                        try:
                                            tPoint[ediff.strip()] += 1  # add to temp ruleset
                                        except:
                                            tPoint[ediff.strip()] = 1
                tmp = extract
            else:
                for data in extract:
                    result = jsbeautifier.beautify(data)  # beautifly the code
                    tmp.append(result)

        # pre check for length
        for m in mPoint:
            if len(m) > 100:
                mPoint.remove(m)  # temporary action :( I will solve it

        for mstr in mPoint:
            self.create_yara(mstr, ystruct)

        yw = YaraWriter(self.yarafile, ystruct)
        yw.write()
        del yw

        # testing compile yara pattern

        try:
            y = yara.compile(self.yarafile)
            print("Yara file compile success!")
        except Exception as e:
            print("Yara file compile failure")
            print(e)

    def create_yara(self, learnstr, ystruct):
        randomname = ''.join(random.sample(string.ascii_uppercase + string.ascii_lowercase + string.digits, 8))
        # create random rulename
        rulename = "$%0.10s" % randomname
        ruleset = '"{0}" nocase'.format(learnstr.replace("\"", "\\\""))
        ystruct.ruleset.append([rulename, ruleset])

    def __del__(self):
        del self
