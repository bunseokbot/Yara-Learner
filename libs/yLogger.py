import logging


class LoggingFramework:
    """ Yara Learner Logging Framework """
    def __init__(self):
        self.logger = logging.getLogger('yLogger')
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter("[%(levelname)s|%(filename)s:%(lineno)s] %(asctime)s >> %(message)s")

        fHandle = logging.FileHandler("yaralearn.log")
        sHandle = logging.StreamHandler()

        fHandle.setFormatter(formatter)
        sHandle.setFormatter(formatter)

        self.logger.addHandler(fHandle)
        self.logger.addHandler(sHandle)

    def __del__(self):
        del self
