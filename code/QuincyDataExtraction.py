import collections
import datetime
import logging
import os
import platform
import signal
import sys
import tempfile
import time
from json import load

import QuincyConfig
import dump_generation.VirtualBox
from QuincyConfig import profiles, characteristics
from QuincyScan import QuincyScan
from dump_generation.MemoryDumpGenerator import MemoryDumpGenerator
from util import QuincyDatabase
from util import QuincyUtils
from util.QuincyParser import QuincyDataExtractionParser
from volatility_interface.VolatilityInterface import Process
from sklearn import __version__

job = None

class FeatureExtractor(object):

    def __init__(self, os_, database_, overwrite=False):
        self.profile = profiles[os_]
        self.characteristics = characteristics
        self._db = database_
        assert isinstance(self._db, QuincyDatabase.Database)
        self.overwrite = overwrite

    def extract(self):
        logging.info("Starting feature extraction")
        dumps = self._db.iterDumps()
        i = 0
        for dump in dumps:
            i += 1
            logging.info("Current dump number is %i" % i)
            logging.info("Extracting from dump %r" % (dict((key, dump[key]) for key in dump if key != "results")))
            try:
                if 'results' not in dump:
                    todo = self.characteristics
                else:
                    todo = [c for c in self.characteristics
                            if not all(
                            c.__name__.split('.')[-1] in process['results'] for process in dump['results'].values())]
                if not todo:
                    logging.info("All features already extracted. Skipping dump.")
                    continue
                self.extract_from_dump(dump, todo)
            except IOError as e:
                if e.errno != 2:
                    raise
                logging.warning(
                    'Could not find dump file of %r (%s). Skipping dump %r' % (dump['path'], e, dump['name']))
            except Exception as e:
                logging.warning('Could not process dump %r (%s)' % (dump['path'], e))
                raise
        logging.info("Finished feature extraction")

    def extract_from_dump(self, dump, characteristics):
        entries = dict()
        if 'results' in dump:
            entries = dump['results'].copy()
        path = dump['path']
        if os.path.exists(path):
            logging.disable(logging.CRITICAL)
            scanner = QuincyScan(path, profile=self.profile)
            logging.disable(logging.NOTSET)
            scanner.extract_features(characteristics)
            scanner.cleanup()
            self.__add_scanner_results_to_db(entries, scanner)
            self._db.addDumpResults(dump, entries)
        else:
            logging.error("Memory dump %s: file does not exist! Continuing..." % path)

    def __add_scanner_results_to_db(self, entries, scanner):
        for process in scanner.processes:
            assert isinstance(process, Process)
            pid = str(process.Id)
            if pid not in entries:
                entries[pid] = {
                    'name': process.Name,
                    'results': self.__get_results(scanner, str(process.Id))
                }
            else:
                entries[pid]['results'].update(self.__get_results(scanner, str(process.Id)))

    def __get_results(self, scanner, pid):
        results = {}
        for characteristic in scanner.feature_results:
            if str(pid) in characteristic[1]:
                results[characteristic[0]] = characteristic[1][str(pid)]
            else:
                logging.warning("No result from %r for pid %r", characteristic[0], pid)
                results[characteristic[0]] = []
        return results


class QuincyDataExtraction(object):

    def __init__(self, os_, verbose=False):
        self.os = os_
        self.verbose = verbose
        self._db = QuincyDatabase.Database(QuincyConfig.hostname, QuincyConfig.port, db_name=os_)
        self.paused = False
        QuincyConfig.vm['name'] = QuincyConfig.vm['machines'][self.os]

    def signal_handler_pause(self, signum, frame):
        logging.warning("Got signal SIGUSR1. Pausing...")
        self.paused = True

    def signal_handler_unpause(self, signum, frame):
        logging.warning("Got signal SIGUSR2. Unpausing...")
        self.paused = False

    def feedSamples(self, path, classification, overwrite):
        logging.info('Inserting %s samples from "%s" into database' % (classification, path))
        if os.path.isfile(path):
            success = self._db.addSample(path, classification, overwrite)
            if success:
                logging.info("Successfully inserted sample %s", path)
            else:
                logging.info("No sample added")
            return

        samples = os.listdir(path)
        if not samples:
            logging.warning('Directory "%s" is empty. Exiting' % path)
            return

        num_samples_added = 0
        for sampleName in samples:
            sample_path = os.path.join(path, sampleName)
            success = self._db.addSample(sample_path, classification, overwrite)
            if success:
                num_samples_added += 1

        if num_samples_added:
            logging.info("Successfully inserted %s samples", num_samples_added)
        else:
            logging.info("No sample added")

    def generate_dumps(self, path, overwrite):
        logging.info('Creating test_data at "%s"' % path)
        for classification in ['malicious', 'benign']:
            samples = list(self._db.getSamples(classification))
            generator = MemoryDumpGenerator(QuincyConfig.vm, silent=(not self.verbose), no_autorun=True)
            if classification == 'benign':  # reduce execution time for beingn samples
                generator.settings['time'] /= 2
            j, n = (0, len(samples))
            logging.info('Found %d %s samples' % (n, classification))
            for i, sample in enumerate(samples):
                if not overwrite and self._db.dumpExists(sample['_id']):
                    logging.info('(%d/%d) Skipping "%s"' % (i + 1, n, sample['name']))
                    continue
                logging.info('(%d/%d) Generating dump "%s"' % (i + 1, n, sample['name']))
                outpath = self.__get_outpath(path, sample)
                entry = self.__get_entry(outpath, sample)
                try:
                    self.__generate_dump(generator, outpath, sample)
                    time.sleep(1)  # unlockMachine doesn't unlock immediately
                    self._db.addDumpInfo(entry, overwrite)
                    j += 1
                except dump_generation.VirtualBox.VBoxException as e:
                    logging.error("Error while dumping %r: ", sample["name"], exc_info=e)
                except Exception as e:
                    logging.error("Unexpected error while dumping %r: ", sample["name"], exc_info=e)
                self.__check_if_paused()

    def __check_if_paused(self):
        if self.paused:
            logging.warning("Execution paused. ")
            print "Press enter to continue."
            # Clearing stdin to prevent previous input to cause continuation
            QuincyUtils.clear_stdin()
            self.__pause()

    def __pause(self):
        while self.paused:
            if QuincyUtils.enter_pressed:
                self.paused = False
            time.sleep(1)
        logging.warning("Continuing")

    def __generate_dump(self, generator, outpath, sample):
        dir = "/dev/shm"
        if "Darwin" in platform.platform():
            dir = "/tmp"
        with tempfile.NamedTemporaryFile(dir=dir, prefix=sample["name"] + "_", mode='w+b') as sample_file:
            raw = self._db.getSampleBinary(sample['raw'])
            sample_file.write(raw)
            sample_file.flush()
            generator.generate(outpath, sample_file.name)

    def __get_entry(self, outpath, sample):
        entry = {
            '_id': sample['_id'],
            'name': sample['name'],
            'path': outpath,
            'infected': list()
        }
        return entry

    def __get_outpath(self, path, sample):
        outdir = os.path.join(path, sample['classification'])
        if not os.path.exists(outdir):
            os.makedirs(outdir)
        outpath = os.path.join(outdir, sample['name'] + '.gz')
        return outpath

    def add_ground_truth(self, path):
        logging.info('Adding ground truth from "%s"' % path)
        with open(path, 'r') as f:
            data = load(f)
        for dump in self._db.iterDumps():
            if dump['name'] in data:
                self._db.addGroundTruthToDump(dump, data[dump['name']])

    def __isMaliciousDump(self, p):
        return "malicious" in p

    def create_ground_truth(self, paths):
        dumps = [dump['path'] for dump in self._db.iterDumps() if self.__isMaliciousDump(dump['path'])]
        groundTruthFile = "ground_truth_%s_%s.json" % (self.os, datetime.datetime.now().strftime('%F_%T'))
        os.system("util/QuincyCreateGroundTruth.py --os %s --yara-signature-path %s --dumps %s > %s" %
                  (self.os, " ".join(paths), " ".join(dumps), groundTruthFile))

    def extract_features(self, overwrite):
        logging.info('Extracting features from the test_data in the database')
        fc = FeatureExtractor(self.os, self._db, overwrite)
        fc.extract()

    def __get_vad_results(self, exportable_features, results):
        vadDict = collections.defaultdict(list)
        for exportable_feature in exportable_features:
            if exportable_feature in results:
                # ToDo: FIXME!
                if type(results[exportable_feature]) == float:
                    print "SOMETHING BROKEN"
                    print exportable_feature, results[exportable_feature]
                    continue
                for k, v in results[exportable_feature].iteritems():
                    vadDict[k] += [v]
            else:
                for k in vadDict.iterkeys():
                    vadDict[k] += ["NAN"]
        return vadDict

    def _is_infected(self, pid, vad, infected_vads):
        for infected_vad in infected_vads:
            if int(pid) == int(infected_vad[0]):
                vadName = hex(int(infected_vad[1])) + "_" + hex(int(infected_vad[2]))
                if vadName in vad:
                    return True
        return False

    def export_raw_data(self, path):
        exportable_features = []
        for c in QuincyConfig.characteristics:
            characteristic_name = c.__name__.split('.')[-1]
            exportable_features.append(characteristic_name)
        exportable_features = sorted(exportable_features)
        logging.info("There are %i features to be exported: %s" % (len(exportable_features), exportable_features))

        out_file = open(path, "w")
        header = "vad"
        for feature in exportable_features:
            header += "," + feature
        header += ",ground_truth\n"
        out_file.write(header)

        for dump in self._db.iterDumps():
            logging.info("exporting %r", dump["name"])
            name = dump["name"]
            infected_vads = []
            if "infected" in dump:
                infected_vads = dump["infected"]
            if "results" in dump:
                for res in dump["results"]:
                    # current process
                    proc_prefix = name + "_" + res

                    vad_results = self.__get_vad_results(exportable_features, dump["results"][res]["results"])
                    for k in vad_results.iterkeys():
                        row = proc_prefix + "_" + k
                        for feat in vad_results[k]:
                            row += "," + str(feat)
                        if self._is_infected(res, k, infected_vads):
                            row += ",0"
                        else:
                            row += ",1"
                        row += "\n"
                        if not "None" in row:
                            out_file.write(row)
                        else:
                            logging.error("Invalid feature values for %s" % proc_prefix)
            else:
                logging.info("\tDump %r has no results", dump["name"])
        out_file.close()

        logging.info("Exported raw test_data to %s" % path)

def watchdog():
    try:
        start_time = datetime.datetime.now()
        main()
        runtime = str(datetime.datetime.now() - start_time).split('.')[0]
        msg = "Finished %r. Runtime: %s" % (job, runtime)
    except:
        try:
            from traceback import format_exc
            msg = '[CRASH] python quincy_data_extraction.py %s' % (' '.join(sys.argv[1:]))
            msg += '\n' + format_exc()
            logging.info(msg)
        finally:
            raise

def init(args):
    format_ = "%(asctime)s;%(levelname)s;%(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format=format_, datefmt=date_format)

    if args.logfile:
        file_handler = logging.FileHandler(args.logfile)
        file_handler.setFormatter(logging.Formatter("%(asctime)s:%(levelname)-5s:%(message)s"))
        logger = logging.getLogger('')
        logger.addHandler(file_handler)
        logger.setLevel(logging.DEBUG)
        logging.debug("Command: %r", ' '.join(sys.argv))

    global job
    job = args.function


def main():
    parser = QuincyDataExtractionParser()
    args = parser.parse(sys.argv[1:])

    init(args)

    quincy_extractor = QuincyDataExtraction(args.os.lower(), args.verbose)
    signal.signal(signal.SIGUSR1, quincy_extractor.signal_handler_pause)
    signal.signal(signal.SIGUSR2, quincy_extractor.signal_handler_unpause)
    if args.function == 'feedSamples':
        quincy_extractor.feedSamples(args.path, args.classification, args.overwrite)
    elif args.function == 'generateDumps':
        quincy_extractor.generate_dumps(args.path, args.overwrite)
    elif args.function == 'createGroundTruth':
        quincy_extractor.create_ground_truth(args.path)
    elif args.function == 'addGroundTruth':
        quincy_extractor.add_ground_truth(args.path)
    elif args.function == 'extractFeatures':
        quincy_extractor.extract_features(args.overwrite)
    elif args.function == 'exportRawData':
        quincy_extractor.export_raw_data(args.path)


if __name__ == '__main__':
    print('The scikit-learn version is {}.'.format(__version__))
    watchdog()
