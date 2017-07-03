import argparse


class CommandLineParser(object):
    parser = None
    args = None
    values = None

    def __init__(self, args):
        self.args = args
        self.parser = argparse.ArgumentParser(
            description="This program can be used to infect a virtualmachine with given malware samples one by one, dumping the memory for further analysis, then recovering to the last clean state.")

        self.parser.add_argument("-s", "--samples", metavar="path",
                                 help="path to a malware sample, or a folder containing malware samples", type=str,
                                 required=True)
        self.parser.add_argument("-t", "--time", help="time to wait after executing the malware", type=int,
                                 required=False, default=120)
        self.parser.add_argument("-n", "--vmname", metavar="name", help="name of the virtual machine to use", type=str,
                                 required=True)
        self.parser.add_argument("-o", "--outputpath", metavar="path",
                                 help="path where the test_data and description are stored", type=str, required=True)
        self.parser.add_argument("-i", "--installmethod", metavar="method", choices=['copy', 'iso'],
                                 help="install malware sample by \"copy\" (needs guest additions installed in vm guest), or by an \"iso\" image",
                                 type=str, required=False, default="copy")
        self.parser.add_argument("-u", "--username", metavar="user", help="name of the vm os user", type=str,
                                 required=True)
        self.parser.add_argument("-p", "--password", metavar="pass", help="password of the given vm user", type=str,
                                 required=False, default="")
        self.parser.add_argument("--raw", action='store_true', help="do not gzip-compress the memory test_data",
                                 required=False, default=False)
        self.parser.add_argument("--silent", action='store_true', help="don't print info messages to stdout",
                                 required=False, default=False)
        self.parser.add_argument("--showvbox", action='store_true',
                                 help="show the virtualbox window (default is headless mode)")
        self.parser.add_argument("--compress", action='store_true', help="compress the dump")
        self.parser.add_argument("--overwrite", action='store_true', help="overwrite existing test_data")
        self.parser.add_argument("--notify", action='store_true', help="send desktop notification before dumping")

    def parse(self):
        return vars(self.parser.parse_args(self.args))
