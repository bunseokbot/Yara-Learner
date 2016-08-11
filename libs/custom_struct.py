class YaraStruct:
    def __init__(self):
        self.rulename = None
        self.ruleset = []
        self.rulecond = None

    def __del__(self):
        del self
