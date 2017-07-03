# The MIT License (MIT)
# Copyright (c) [2015] Thomas Barabosch, Niklas Bergmann, Adrian Dombeck, Elmar Gerhards-Padilla
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all copies or substantial portions
# of the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
# NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
# OR OTHER DEALINGS IN THE SOFTWARE.
import json
import unittest
import sys
import os
import subprocess

sys.path.append(os.path.abspath("../code"))
import QuincyScan
import QuincyConfig

ACCEPT_RATE = 0.75

class TestQuincyScan(unittest.TestCase):

    def __is_detected(self, ground_truth_vad, detected_vads):
        for detected_vad in detected_vads:
            if detected_vad.process_id == int(ground_truth_vad[0]) and detected_vad.vad_start == int(ground_truth_vad[1]):
                return True
        return False

    def __is_family_detected(self, family, res):
        detected_malicious_vads = [x for x in res if x.result == QuincyConfig.MALICIOUS]
        groundtruth_malicious_vads = self.ground_truth[family]

        detection_res = []
        for groundtruth_vad in groundtruth_malicious_vads:
            print "Groundtruth: process %i at 0x%x" % (groundtruth_vad[0], groundtruth_vad[1])
            quincy_vad_res = self.__is_detected(groundtruth_vad, detected_malicious_vads)
            detection_res.append(quincy_vad_res)
            if not quincy_vad_res:
                print ("Quincy has not detected the groundtruth vad 0x%x in process %i" % (groundtruth_vad[1],
                                                                                              groundtruth_vad[0]))
        true_positives = detection_res.count(True)
        if float(true_positives) / float(len(detection_res)) <= ACCEPT_RATE:
            self.fail("Qunicy failed to detect the family in less than %i percent of the cases (%i/%i)" %
                      (ACCEPT_RATE * 100, true_positives, len(detection_res)))


    def setUp(self):
        print("Decrypting test data...")
        subprocess.call("sh ./decrypt_test_data.sh", shell=True)

        self.ground_truth = json.load(open("test_data/groundtruth_examples.json"))
        self.custom_model = "./test_data/winxp_sp2_without_spyeye_teerac_zeus.json"

    def tearDown(self):
        print("Removing decrypted test data...")
        try:
            os.remove("test_data/spyeye_winxp.gz")
            os.remove("test_data/teerac_winxp.gz")
            os.remove("test_data/zeus_winxp.gz")
        except:
            print("Could not remove test data, you may need to clean the *.gz files...")

    def test_xp_spyeye(self):
        quincy_scan = QuincyScan.QuincyScan(path="./test_data/spyeye_winxp.gz", custom_model=self.custom_model)
        res = quincy_scan.scan()
        self.__is_family_detected("spyeye", res)

    def test_xp_teerac(self):
        quincy_scan = QuincyScan.QuincyScan(path="./test_data/teerac_winxp.gz", custom_model=self.custom_model)
        res = quincy_scan.scan()
        self.__is_family_detected("teerac", res)

    def test_xp_zeus(self):
        quincy_scan = QuincyScan.QuincyScan(path="./test_data/zeus_winxp.gz", custom_model=self.custom_model)
        res = quincy_scan.scan()
        self.__is_family_detected("zeus", res)

if __name__ == '__main__':
    unittest.main()