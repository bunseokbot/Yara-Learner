import glob
import os
import re

from libs.custom_struct import YaraStruct


class YaraFileParser:
    """ Yara file parser """
    def __init__(self, yarafile, yaraflag):
        self.yarafile = yarafile
        self.yaraflag = yaraflag
        self.fileflag = ''
        self.ystrlist = []

    def action(self):
        yfList = []

        if self.yaraflag:  # if directory
            fList = glob.glob(os.path.join(self.yarafile, '*'))
            yfList = list(filter(lambda x: yfList.append(x), fList))
        else:
            yfList.append(self.yarafile)

        for yfile in yfList:
            stream = self.read_filestream(yfile)
            self.get_yarastruct(stream)


    def read_filestream(self, fname):
        f = open(fname, 'rb')
        data = f.read()
        f.close()

        data = data.decode()

        return data

    def get_yarastruct(self, stream):
        rulere = re.compile(r'rule (.*?) {\n(.*?)\n}', re.DOTALL)
        rulelist = re.findall(rulere, stream)

        for rulename, rulebody in rulelist:
            y = YaraStruct()
            y.rulename = rulename
            for row in rulebody.replace('\t', '').split('\n'):
                self.read_yaraline(row, y)
            self.ystrlist.append(y)

    def read_yaraline(self, row, y):
        if row == "strings:":
            self.fileflag = 'str'
        elif row == "condition:":
            self.fileflag = 'cond'
        elif len(row) == 0:
            pass
        else:
            y = self.read_deepyaraline(row, y)

        return y

    def read_deepyaraline(self, row, y):
        if self.fileflag == 'str':
            rulename, rulebody = row.split(' = \"')
            y.ruleset.append([rulename, "\"" + rulebody])

        if self.fileflag == 'cond':
            y.rulecond = row.strip()

        return y

    def __del__(self):
        del self
