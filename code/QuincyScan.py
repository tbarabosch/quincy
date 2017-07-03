import os
import sys
import time
import logging
import pickle
import json
import coloredlogs
import pandas as pd
import hexdump
import hashlib
import zlib
import collections
from sklearn import preprocessing, __version__

import QuincyConfig
from volatility_interface.VolatilityInterface import VolatilityInterface
from util.QuincyParser import QuincyDetectParser

from util import QuincyVirusTotalScan
from util import QuincyUtils
from features import malfind
from features import hollowfind

class ScanResult(object):

    def __init__(self, process_id, vad_start, vad_end, result):
        self.process_id = process_id
        self.vad_start = vad_start
        self.vad_end = vad_end
        self.result = result

class QuincyScan(object):

    def __init__(self, path, custom_model=None, profile='WinXPSP2x86', with_malfind=False, with_hollowfind=False,
                 prefilter=None):
        coloredlogs.install()

        self.profile = profile
        self.path = path
        self.withMalfind = with_malfind
        self.withHollowfind = with_hollowfind
        if custom_model is not None:
            self.model, self.model_discarded_features = self.__load_model(custom_model)
        self.__init_extract_dump(path, profile)
        self.__init_volatility(profile)
        self.scan_results = []
        self.feature_results = []
        self.__load_prefilter(prefilter)

    def __init_volatility(self, profile):
        logging.debug("Initializing Volatility")
        logging.disable(logging.CRITICAL)
        self.vi = VolatilityInterface(self.path, profile)
        logging.disable(logging.NOTSET)
        self.processes = self.vi.Processes
        self.threads = self.vi.Threads

    def __init_extract_dump(self, path, profile):
        logging.debug("Initializing the dump.")
        self.temp = QuincyUtils.tryExtractDump(path, profile)
        if self.temp:
            self.path = self.temp

    def __is_compressed(self, data):
        try:
            zlib.decompress(data)
            return True
        except:
            return False

    def __load_prefilter(self, prefilter):
        if prefilter:
            logging.info("Loading prefilter...")
            with open(prefilter, "r") as f:
                vad_lines = f.readlines()

            self._prefilter_map = collections.defaultdict()

            for vad_line in vad_lines:
                split_line = vad_line.strip().split(",")
                key = split_line[0] + "_" + split_line[1] + "_" + split_line[2]
                self._prefilter_map[key] = split_line[3]

            self._prefilter = True
        else:
            self._prefilter = False

    def __load_model(self, path_model_description):
        logging.debug("Loading model description %s" % path_model_description)
        model_description = json.load(open(path_model_description))

        model_path = path_model_description.replace(".json", ".model")
        logging.info("Loading model %s from %s" % (model_description["model_name"], model_path))
        logging.info("Model is based on classifier %s" % model_description["classifier"]["classifier"])

        with open(model_path, "rb") as f:
            model_data = f.read()

        if self.__is_compressed(model_data):
            logging.info("Model is zipped. Unzipping...")
            model = pickle.loads(model_data.decode("zlib"))
        else:
            model = pickle.loads(model_data)

        discarded_features = []
        if 'feature_selection_results' in model_description:
            discarded_features = model_description['feature_selection_results']['discarded']
            logging.info("Model discards the following features: %s" % str(discarded_features))

        if "scaling" in model_description:
            if model_description["scaling"]:
                logging.info("Model requires data scaling.")
            self._scaling = model_description["scaling"]
        else:
            self._scaling = False



        return model, discarded_features

    def scan(self):
        characteristics_without_other_heuristics = self.__get_features()
        self.extract_features(characteristics_without_other_heuristics)
        results = self.__detect()
        return results

    def __run_module(self, module):
        logging.info('Running "%s" ...' % module.__name__)
        start = time.clock()
        try:
            results = module.scan(self)
        except Exception, e:
            logging.warning('Module "%s" has failed (%s)' % (module, e))
            raise

        logging.debug('Completed scan in %.2f seconds' % (time.clock() - start))
        return results

    def __remove_unpacked_dump(self):
        if self.temp and os.path.exists(self.temp):
            logging.info("Removing unpacked dump at %s" % self.temp)
            try:
                os.remove(self.temp)
            except:
                logging.error("Could not remove unpacked dump at %s" % self.temp)

    def __is_discarded_feature(self, feature_name):
        for d in self.model_discarded_features:
            if d == feature_name:
                return True
        return False

    def __get_features(self):
        valid_features = []
        logging.info("There are %i features available." % (len(QuincyConfig.characteristics) - 2))
        for c in QuincyConfig.characteristics:
            feature_name = c.__name__.split('.')[-1]
            if feature_name != "malfind" and feature_name != "hollowfind" and not self.__is_discarded_feature(
                    feature_name):
                valid_features.append(c)
                logging.debug("Adding feature: %s" % feature_name)
            else:
                logging.debug("Discarding feature: %s" % feature_name)
        logging.info("After discarding using %i features." % len(valid_features))
        return valid_features

    def extract_features(self, characteristics_):
        start = time.clock()

        for characteristic in characteristics_:
            self.__extract_feature(characteristic)

        logging.info('Finished all scans in %.2f seconds' % (time.clock() - start))

    def __extract_feature(self, characteristic):
        logging.debug("Scanning for %s" % characteristic)
        characteristic_name = characteristic.__name__.split('.')[-1]
        try:
            self.feature_results.append((characteristic_name, self.__run_module(characteristic)))
        except Exception, e:
            logging.warning('Could not load module "%s" (%s)' % (characteristic.__name__, e))
            raise

    def __hash_vad(self, vad):
        hash_obj = hashlib.sha256(vad.read())
        return hash_obj.hexdigest()

    def __detect(self):
        malfind_results = None
        if self.withMalfind:
            logging.info("Running malfind as heuristic.")
            malfind_results = malfind.scan(self)

        hollowfind_results = None
        if self.withHollowfind:
            logging.info("Running hollowfind as heuristic.")
            hollowfind_results = hollowfind.scan(self)

        self.scan_results = []
        for process in self.processes:
            logging.debug("Current process: %i" % process.Id)
            if malfind_results is not None:
                malfind_results_for_process = malfind_results[str(process.Id)]
            else:
                malfind_results_for_process = None
            if hollowfind_results is not None:
                hollowfind_results_for_process = hollowfind_results[str(process.Id)]
            else:
                hollowfind_results_for_process = None

            for vad in process.VADs:
                if self._prefilter:
                    key = str(process.Id) + "_" + str(vad.Start) + "_" + str(vad.End)
                    if key in self._prefilter_map:
                        hash = self.__hash_vad(vad)
                        if hash == self._prefilter_map[key]:
                            logging.info("Prefiltered PID %i VAD 0x%x (%s)" % (process.Id, vad.Start, hash))
                            continue

                self.scan_results.append(self.__detect_vad(malfind_results_for_process,
                                                           hollowfind_results_for_process, process, vad))

        return self.scan_results

    def __hexdump_vad_start(self, pid, vadStart):
        for process in self.processes:
            if process.Id == pid:
                data = process.read(vadStart, QuincyConfig.HEXDUMP_BYTES)
                hexdump.hexdump(data)
                return

    def __detect_vad(self, malfind_results_for_process, hollowfind_results_for_process, process, vad):
        logging.debug('\t#%d "%s" VAD 0x%x with size 0x%x' % (process.Id, process.Name, vad.Start, vad.End - vad.Start))

        if malfind_results_for_process is not None:
            malfind_result_for_vad = malfind_results_for_process[hex(vad.Start)[:-1] + "_" + hex(vad.End)[:-1]]

        if hollowfind_results_for_process is not None:
            hollowfind_result_for_vad = hollowfind_results_for_process[hex(vad.Start)[:-1] + "_" + hex(vad.End)[:-1]]

        vad_results = self.__get_vad_results(process, vad)
        vad_data = pd.DataFrame.from_dict(vad_results)
        if self._scaling:
            vad_data = preprocessing.scale(vad_data)
        modelPrediction = self.model.predict(vad_data)

        if modelPrediction == QuincyConfig.MALICIOUS:
            self.__log_malicious_vad(malfind_result_for_vad if malfind_results_for_process is not None else None,
                                     malfind_results_for_process,
                                     hollowfind_result_for_vad if hollowfind_results_for_process is not None else None,
                                     hollowfind_results_for_process,
                                     process, vad, vad_results)
        else:
            self.__log_benign_vad(malfind_result_for_vad if malfind_results_for_process is not None else None,
                                  malfind_results_for_process,
                                  hollowfind_result_for_vad if hollowfind_results_for_process is not None else None,
                                  hollowfind_results_for_process,
                                  process, vad)
        return ScanResult(process.Id, vad.Start, vad.End, modelPrediction)

    def __get_vad_results(self, process, vad):
        vad_results = {}
        for feature in self.feature_results:
            if str(process.Id) in feature[1]:
                for vadRes in feature[1][str(process.Id)]:
                    name = hex(vad.Start)[:-1] + "_" + hex(vad.End)[:-1]
                    if name in vadRes:
                        vad_results[feature[0]] = [feature[1][str(process.Id)][vadRes]]
        logging.debug("\t\t%s" % str(vad_results))
        return vad_results

    def __log_benign_vad(self, malfind_result_for_vad, malfind_results_for_process, hollowfind_result_for_vad,
                         hollowfind_results_for_process, process, vad):
        logging.debug('Process: %i, VAD 0x%x is clean!' % (process.Id, vad.Start))
        if malfind_results_for_process is not None and malfind_result_for_vad == QuincyConfig.MALICIOUS:
            logging.debug(
                'Missmatch with malfind! It says process: %i, VAD 0x%x is INFECTED!' % (process.Id, vad.Start))
        if hollowfind_results_for_process is not None and hollowfind_result_for_vad == QuincyConfig.MALICIOUS:
            logging.debug(
                'Missmatch with hollowfind! It says process: %i, VAD 0x%x is INFECTED!' % (process.Id, vad.Start))

    def __log_malicious_vad(self, malfind_result_for_vad, malfind_results_for_process, hollowfind_result_for_vad,
                            hollowfind_results_for_process, process, vad, vad_results):
        logging.critical(
            'Process: %i, VAD 0x%x is INFECTED!' % (process.Id, vad.Start))
        self.__hexdump_vad_start(process.Id, vad.Start)
        if malfind_results_for_process is not None:
            if malfind_result_for_vad == QuincyConfig.MALICIOUS:
                logging.critical("Malfind says also that process: %i, VAD 0x%x is INFECTED!" % (process.Id, vad.Start))
            else:
                logging.critical("Missmatch with malfind! According to malfind process: %i, VAD 0x%x is CLEAN!" % (
                    process.Id, vad.Start))
        if hollowfind_results_for_process is not None:
            if hollowfind_result_for_vad == QuincyConfig.MALICIOUS:
                logging.critical("Hollowfind says also that process: %i, VAD 0x%x is INFECTED!" %
                                 (process.Id, vad.Start))
            else:
                logging.critical("Missmatch with hollowfind! According to hollowfind process: %i, VAD 0x%x is CLEAN!"
                                 % (process.Id, vad.Start))
        logging.debug("\t\t%s" % str(vad_results))

    def virus_total_scan(self):
        vtScan = QuincyVirusTotalScan.QuincyVirusTotalScan(self.processes, self.scan_results)
        vtScan.scan()

    def cleanup(self):
        logging.info("Cleaning up unpacked dump.")
        self.__remove_unpacked_dump()

def get_precomputed_model(profile):
    for m in QuincyConfig.PRECOMPUTED_MODELS.iterkeys():
        if m in profile.lower():
            return QuincyConfig.PRECOMPUTED_MODELS[m]

    logging.error("Could not find precomputed model for Volatility profile %s" % profile)
    raise Exception("No precomputed model available.")

def main(args=None):

    if args is None:
        args = sys.argv[1:]

    parser = QuincyDetectParser()
    arguments = parser.parse(args)
    QuincyUtils.set_up_logging(arguments['verbose'])

    # clear args so we dont mess up volatility
    sys.argv = list()

    if "custom_model" in arguments and arguments["custom_model"] is not None:
        model = arguments["custom_model"]
    else:
        model = get_precomputed_model(arguments["profile"])

    try:
        quincyScan = QuincyScan(path=arguments['dump'],
                                custom_model=model,
                                profile=arguments['profile'],
                                with_malfind=arguments["with_malfind"],
                                with_hollowfind=arguments["with_hollowfind"],
                                prefilter=arguments["prefilter"])
        quincyScan.scan()

        if arguments["with_virustotal"]:
            quincyScan.virus_total_scan()
    finally:
        quincyScan.cleanup()

if __name__ == "__main__":
    print('The scikit-learn version is {}.'.format(__version__))
    main()
