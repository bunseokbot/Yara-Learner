
class YaraWriter:
    def __init__(self, fname, yarastruct):
        self.fname = fname
        self.yarastruct = yarastruct

    def write(self): 
        tmp = []
        f = open(self.fname, 'w')

        data = "rule %s {\n" % self.yarastruct.rulename
        data += "\tstrings:\n"
        for rulename, ruledata in self.yarastruct.ruleset:
            if ruledata not in tmp:
                data += "\t\t%s = %s\n" % (rulename, ruledata)
                tmp.append(ruledata)
        data += "\n\tcondition:\n"
        data += "\t\t%s\n" % self.yarastruct.rulecond
        data += "}"

        f.write(data)

        f.close()

    def __del__(self):
        del self
