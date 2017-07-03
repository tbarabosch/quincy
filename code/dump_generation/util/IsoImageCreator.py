import os
import tempfile
import logging
import argparse

import shutil
import utils

# IsoImgeCreator
GENISOIMAGE = "/usr/bin/genisoimage"
GENISOIMAGE_OPTIONS = " -J -R"  # Joilet, RockRidge
GENISOIMAGE_LOG_TARGET = "/dev/null"


class IsoImageCreator(object):

    def __init__(self, output_path=None, no_autorun=False):
        if output_path:
            self.output_path = output_path
        else:
            self.output_path = tempfile.mkstemp(suffix=".iso")[1]
        self.no_autorun = no_autorun

    def construct_gen_iso_image_call(self, input_path, output_path):
        return "{0} {1} -o {2} {3} > {4} 2>&1".format(GENISOIMAGE, GENISOIMAGE_OPTIONS, output_path, input_path,
                                                      GENISOIMAGE_LOG_TARGET)

    @staticmethod
    def create_autorun_inf(image_dir, executable_name):
        fname = os.path.join(image_dir, "AUTORUN.INF")
        with open(fname, "w") as f:
            f.write("[Autorun]")
            f.write('\r\n')
            f.write("Open={0}".format(executable_name))

    def create_batch_script(self, image_dir, executable_name):
        fname = os.path.join(image_dir, "move.bat")
        with open(fname, "w") as f:
            f.write("@echo off\r\n")
            f.write('copy %s "%%USERPROFILE%%\Desktop\%s.exe"\r\n' % (executable_name, executable_name))
            f.write('"%%USERPROFILE%%\Desktop\%s.exe"' % executable_name)

    @staticmethod
    def is_pe_file(path):
        if not os.path.isfile(path):
            return False
        with open(path) as f:
            return f.read(2) == "MZ"

    def write_image(self, image_dir, output_path):
        os.system(self.construct_gen_iso_image_call(image_dir, output_path))

    def create_image(self, path):
        logging.info("compressing %r to iso image %r", path, self.output_path)
        with utils.temporaryDirectory() as image_dir:
            self.copy(path, image_dir)
            if not self.no_autorun and self.is_pe_file(path):
                logging.info("%r is an executable. creating autorun.inf", path)
                self.create_batch_script(image_dir, os.path.basename(path))
                self.create_autorun_inf(image_dir, 'move.bat')
            self.write_image(image_dir, self.output_path)
        return self.output_path

    def copy(self, path, image_dir):
        if os.path.isdir(path):
            shutil.copytree(path, os.path.join(image_dir, os.path.basename(path)))
        else:
            shutil.copy(path, image_dir)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", metavar="<path>")
    parser.add_argument("-o", "--output", metavar="<output path>", help="output path")
    parser.add_argument("--no-autorun", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")

    return parser.parse_args()


def init(args):
    if args.verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(level=level)


def main():
    args = parse_args()
    init(args)
    path = os.path.abspath(args.path)
    if args.output:
        output_path = os.path.abspath(args.output)
    else:
        output_path = os.path.abspath(path) + ".iso"

    iso_creator = IsoImageCreator(output_path, no_autorun=args.no_autorun)
    iso_creator.create_image(path)


if __name__ == "__main__":
    main()
