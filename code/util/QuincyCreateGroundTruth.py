#!/usr/bin/env python
import os
import argparse
import subprocess
import re
import json
import logging

import os.path, sys

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
from QuincyUtils import extract_if_packed
from QuincyConfig import profiles

VOLATILITY = "vol.py"

def parse_args():
    parser = argparse.ArgumentParser(
        description="Run volatility --yarascan with yara signatures on samples and create JSON file containing the "
                    "matching PIDs per sample")
    parser.add_argument("--os", "-os", default="winxp", help="operating system")
    parser.add_argument("--yara-signature-path", "-y", nargs="+", required=True,
                        help="yara signature files or directories which contain the yara signatures")
    parser.add_argument("--dumps", "-d", nargs="+", required=True, help="dumps to create the ground truth from")
    parser.add_argument("--infected-dumped", default=None, help="directory for storing detected dumps")
    return parser.parse_args()

class GroundTruthScanner(object):

    def __init__(self, dumps, dump_infected="", yara_sig_path=None, operating_system=""):
        self.skipped_dumps = []
        self.ground_truth = dict()
        self.dump_infected = dump_infected
        self.yara_sig_path = yara_sig_path
        self.operating_system = operating_system
        self.dumps = dumps

    def parse_yarascan_output(self, output, vads):
        dict_ = eval(output)
        infected_owners = [(row[1], row[2]) for row in dict_["rows"]]
        infected_vads = []
        for owner in infected_owners:
            match = re.search('\(Pid ([0-9]+)\)', owner[0])
            if match:
                pid = int(match.group(1))
                for vad in vads:
                    if pid == vad[0]:
                        if vad[1] < owner[1] and owner[1] < vad[2]:
                            infected_vads.append((pid, vad[1], vad[2]))
        return list(set(infected_vads))

    def find_yara_file(self, search_path, name):
        yara_base_name = name + ".yara"
        if os.path.isdir(search_path):
            for root, dirnames, filenames in os.walk(search_path):
                for filename in filenames:
                    if filename == yara_base_name:
                        return os.path.join(root, filename)
        elif os.path.basename(search_path) == yara_base_name:
            return search_path
        return None

    def get_infected_vads(self, dump, yara_file_path, profile):
        with extract_if_packed(dump) as dump_extracted:
            command = "%s --profile %s -f %s yarascan -y %s --output json" % (
                VOLATILITY, profile, dump_extracted, yara_file_path)
            yara_output = subprocess.check_output(command.split())

            command = "%s --profile %s -f %s vadinfo --output json" % (
                VOLATILITY, profile, dump_extracted)
            vads_output = subprocess.check_output(command.split())
            vads = []
            for vad in json.loads(vads_output)["rows"]:
                vads.append((vad[0], vad[2], vad[3], vad[6]))

        return self.parse_yarascan_output(yara_output, vads)

    def scan_dump(self, dump):
        logging.info("Current dump is %r" % dump)
        basename = os.path.basename(dump).split('.')[0]
        for yara_path in self.yara_sig_path:
            yara_file_path = self.find_yara_file(yara_path, basename)
            if yara_file_path: break
        if not self.yara_sig_path:
            logging.warning('No yara signature file for %r found. Skipping dump %r.' % (basename, dump))
            self.skipped_dumps.append(basename)
        else:
            self.ground_truth[basename] = self.get_infected_vads(dump, yara_file_path, profiles[self.operating_system])

            if self.dump_infected:
                with extract_if_packed(dump) as dump_extracted:
                    for infected in self.ground_truth[basename]:
                        path = os.path.join(self.dump_infected, basename)
                        if not os.path.exists(path):
                            os.mkdir(path)
                        logging.info("Dumping infected VADs for dump %s" % basename)
                        command = "%s --profile %s -f %s vaddump -p %i -b 0x%x -D %s" % (
                            VOLATILITY, profiles[self.operating_system], dump_extracted, infected[0], infected[1], path)
                        subprocess.check_output(command.split())

    def scan(self):
        for dump in self.dumps:
            self.scan_dump(dump)

        return self.ground_truth, self.skipped_dumps

def main():
    args = parse_args()
    logging.basicConfig(level=logging.INFO)

    ground_truth_scanner = GroundTruthScanner(dumps=args.dumps, dump_infected=args.infected_dumped, yara_sig_path=args.yara_signature_path, operating_system=args.os)
    ground_truth, skipped_dumps = ground_truth_scanner.scan()

    print json.dumps(ground_truth, indent=2)
    logging.info("-" * 100)
    logging.info("Skipped dumps: " + str(len(skipped_dumps)))
    logging.info(str(skipped_dumps))

if __name__ == '__main__':
    main()
