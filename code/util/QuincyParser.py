import argparse

class QuincyLearnParser(object):


    def __init__(self):
        self.parser = argparse.ArgumentParser(prog='QuincyLearn',
                                              description='QuincyLearn learns a model that can be used with QuincyDetect')
        self.parser.add_argument('csv', type=str, help='Path to CSV test_data to learn model from')
        self.parser.add_argument('-v', '--verbose', action='store_true', help='Activates verbose output')
        self.parser.add_argument("--classifier",
                                 choices=["DecisionTree", "RandomForest", "ExtraTrees", "AdaBoost", "GradientBoosting", "SVM", "MLP", "KNN"],
                                 default="ExtraTrees", help="The tree-based classifier that is used for learning")
        self.parser.add_argument('--feature_selection', action='store_true', help='Activates feature selection by using'
                                                                                  ' recursive feature eliminiation based'
                                                                                  ' on RandomForest')
        self.parser.add_argument('--undersampling', action='store_true', help='Randomly undersamples the data set such that there '
                                                                            'are not too many benign samples that might '
                                                                            'confuse the classifiers')
        self.parser.add_argument('--scaling', action='store_true',
                                 help='Scales data before learning')
        self.parser.add_argument('model_name', type=str, help='Name of model to learn')
        self.parser.add_argument('model_outpath', type=str, help='Output path of model')

    def parse(self, args):
        return vars(self.parser.parse_args(args))

class QuincyDetectParser(object):


    def __init__(self):
        self.parser = argparse.ArgumentParser(prog='QuincyScan',
                                              description='QuincyDetect scans memory dumnps for Host-Based Code Injection Attacks')
        self.parser.add_argument('dump', type=str, help='Path to the memory dump to analyze.')
        self.parser.add_argument('--custom_model', type=str, help='Path to model description of custom model.')
        self.parser.add_argument('--prefilter', type=str, help='Path to prefilter CSV.', default=None)
        self.parser.add_argument('-v', '--verbose', action='store_true', help='Activates verbose output')
        self.parser.add_argument('--with_malfind', action='store_true', help='Scans also with malfind')
        self.parser.add_argument('--with_hollowfind', action='store_true', help='Scans also with hollowfind')
        self.parser.add_argument('--with_virustotal', action='store_true', help='Uploads detected files to VirusTotal')
        self.parser.add_argument('-vp', '--profile', type=str, default='WinXPSP2x86',
                                 help='The profile used to analyze the memory test_data.')

    def parse(self, args):
        return vars(self.parser.parse_args(args))

class QuincyDataExtractionParser(object):


    def __init__(self):
        self.parser = argparse.ArgumentParser(prog='QuincyDataExtraction',
                                              description='QuincyDataExtraction generates memory dumnps and extracts features from them.')
        self.parser.add_argument("os", type=str, help="Operating system to analyze / whose database to operate on")
        self.parser.add_argument('-v', '--verbose', action='store_true')
        self.parser.add_argument('-l', '--logfile')

        subparsers = self.parser.add_subparsers(dest='function')

        parserFeedSamples = subparsers.add_parser('feedSamples', help="Inserts executable samples into the database")
        parserFeedSamples.add_argument("path", help="Path to directory containing the samples")
        parserFeedSamples.add_argument("classification", choices=["malicious", "benign"])
        parserFeedSamples.add_argument("--overwrite", action="store_true",
                                       help="Overwrite existing documents in the database")

        parserGenerateDumps = subparsers.add_parser('generateDumps',
                                                    help="Executes each of the malware samples in the database inside a VM and creates a memory dump of it")
        parserGenerateDumps.add_argument("path", help="Path to directory to create the test_data in")
        parserGenerateDumps.add_argument("--overwrite", action="store_true",
                                         help="Overwrite existing documents in the database")

        parserCreateGroundTruth = subparsers.add_parser('createGroundTruth',
                                                        help="Determine which processes were infected using yara signatures")
        parserCreateGroundTruth.add_argument("path", nargs="+",
                                             help="Path to yara signature files. Multiple paths can be passed. All will be searched recursively, until a file with name \"$malware_name.yara\" is found")

        parserAddGroundTruth = subparsers.add_parser('addGroundTruth',
                                                     help="Inserts ground truth infection states of processes per dump from a JSON file into the dump documents in the database")
        parserAddGroundTruth.add_argument("path", help="Path to JSON file containing the ground truth test_data")

        parserExtractFeatures = subparsers.add_parser('extractFeatures',
                                                      help="Extract features from the test_data in the database and insert them into the database")
        parserExtractFeatures.add_argument("--overwrite", action="store_true",
                                           help="Overwrite existing documents in the database")

        parserExportRawData = subparsers.add_parser('exportRawData',
                                                    help="Exports raw dump test_data to CSV for test_data analysis")
        parserExportRawData.add_argument("path", help="Path to CSV file")

    def parse(self, args):
        return self.parser.parse_args(args)


class QuincyCreatePrefilterParser(object):


    def __init__(self):
        self.parser = argparse.ArgumentParser(prog='QuincyCreatePrefilter',
                                              description='QuincyCreatePrefilter creates ')
        self.parser.add_argument('clean_dump', type=str, help='Path to clean memory dump to employ as prefilter base.')
        self.parser.add_argument('-v', '--verbose', action='store_true', help='Activates verbose output')
        self.parser.add_argument('-vp', '--profile', type=str, default='WinXPSP2x86',
                                 help='The profile used to analyze the memory dump.')

    def parse(self, args):
        return vars(self.parser.parse_args(args))