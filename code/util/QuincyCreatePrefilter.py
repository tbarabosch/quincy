import sys
import os
import logging
import hashlib

from QuincyUtils import set_up_logging, tryExtractDump
from QuincyParser import QuincyCreatePrefilterParser
sys.path.insert(0,'../volatility_interface')
from VolatilityInterface import VolatilityInterface

class VadInfo(object):


    def __init__(self, pid, start, end, hash):
        self.pid = pid
        self.start = start
        self.end = end
        self.hash = hash

    def __str__(self):
        return "%i,%i,%i,%s" % (self.pid, self.start, self.end, self.hash)

class QuincyCreatePrefilter(object):


    def __init__(self, memory_dump, profile):
        self._memory_dump = memory_dump
        self._profile = profile

        self.__initExtractDump(self._memory_dump, self._profile)
        self.__initVolatility(self._profile)

    def __initVolatility(self, profile):
        logging.debug("Initializing Volatility")
        logging.disable(logging.CRITICAL)
        self.vi = VolatilityInterface(self.path, profile)
        logging.disable(logging.NOTSET)
        self.processes = self.vi.Processes
        self.threads = self.vi.Threads

    def __initExtractDump(self, path, profile):
        self.temp = tryExtractDump(path, profile)
        if self.temp:
            self.path = self.temp

    def __removeUnpackedDump(self):
        if self.temp and os.path.exists(self.temp):
            logging.info("Removing unpacked dump at %s" % self.temp)
            try:
                os.remove(self.temp)
            except:
                logging.error("Could not remove unpacked dump at %s" % self.temp)

    def __hash_vad(self, vad):
        hash_obj = hashlib.sha256(vad.read())
        return hash_obj.hexdigest()

    def create_prefilter(self):
        vad_results = []
        for process in self.processes:
            print process
            for vad in process.VADs:
                vad_results.append(VadInfo(process.Id, vad.Start, vad.End, self.__hash_vad(vad)))

        filename = os.path.split(self._memory_dump)[1] + ".prefilter"
        with open(filename, "w") as f:
            for vad_result in vad_results:
                f.write("%s\n" % vad_result)

    def cleanup(self):
        self.__removeUnpackedDump()

def main():
    args = sys.argv[1:]
    parser = QuincyCreatePrefilterParser()
    arguments = parser.parse(args)
    set_up_logging(arguments['verbose'])

    # clear args so we dont mess up volatility
    sys.argv = list()

    try:
        prefilter = QuincyCreatePrefilter(memory_dump=arguments['clean_dump'],
                                          profile=arguments["profile"])
        prefilter.create_prefilter()
    finally:
        prefilter.cleanup()

if __name__ == "__main__":
    main()