import tempfile
import logging
import json
import os
import time
import sys

from virustotal import vt

sys.path.insert(0,'..')
import QuincyConfig

class QuincyVirusTotalScan(object):


    def __init__(self, processes, scan_results):
        # scanner based on https://github.com/nu11p0inter/virustotal
        self.processes = processes
        self.scan_results = scan_results
        self.vt = vt()
        self.vt.setkey(QuincyConfig.VIRUSTOTAL_KEY)
        self.vt.out('json')

    def __log_virus_total_report(self, report):
        report = json.loads(report)
        logging.info("Sha256: %s" % report["sha256"])
        logging.info("Scan date: %s" % report["scan_date"])
        logging.info("Permalink: %s" % report["permalink"])
        logging.info("Scan result: %s/%s" % (report["positives"], report["total"]))
        for scan in report["scans"]:
            if "detected" in report["scans"][scan]:
                if report["scans"][scan]["detected"] == True:
                    logging.info("\t%s: %s" % (scan, report["scans"][scan]["result"]))

    def scan(self):
        if len(self.scan_results):
            vtResults = []
            for scanResult in self.scan_results:
                res = self.__get_and_scan_vad(scanResult)
                if res is not None:
                    vtResults.append(res)

            self.__get_scan_results(vtResults)

    def __get_and_scan_vad(self, scan_result):
        if scan_result.result == QuincyConfig.MALICIOUS:
            logging.info("Scanning VAD 0x%x of process %i at VirusTotal" %
                         (scan_result.vad_start, scan_result.process_id))

            tmp_file_path = tempfile.mkstemp()[1]
            logging.debug("Tempfile at %s" % tmp_file_path)
            for proc in self.processes:
                if proc.Id == scan_result.process_id:
                    size_of_vad = scan_result.vad_end - scan_result.vad_start
                    logging.debug("Reading %i bytes from process %i at address 0x%x" % (
                        size_of_vad, scan_result.process_id, scan_result.vad_start))
                    tmpFile = open(tmp_file_path, "wb")
                    tmpFile.write(proc.read(scan_result.vad_start, size_of_vad))
                    tmpFile.close()
                    break

            scan_id = self.vt.scanfile(tmp_file_path)["scan_id"]

            try:
                os.remove(tmp_file_path)
            except:
                logging.error("Could not remove tmpfile %s" % tmp_file_path)

            return (scan_result, scan_id)

    def __get_scan_results(self, vt_results):
        if len(vt_results) > 0:
            logging.info("Waiting %i seconds for VirusTotal to scan files" % QuincyConfig.VIRUSTOTAL_WAIT_SCAN)
            time.sleep(QuincyConfig.VIRUSTOTAL_WAIT_SCAN)
            for vt_result in vt_results:
                logging.info("Requesting report for VAD 0x%x of process %i with scan_id %s" % (
                    vt_result[0].vad_start, vt_result[0].process_id, vt_result[1]))
                res = self.vt.getfile(vt_result[1])
                if res is not None:
                    self.__log_virus_total_report(res)
                logging.info("Waiting %i seconds before requesting next scan result" % QuincyConfig.VIRUSTOTAL_WAIT_REQUEST)
                time.sleep(QuincyConfig.VIRUSTOTAL_WAIT_REQUEST)
        else:
            logging.info("No VADs to scan...")
