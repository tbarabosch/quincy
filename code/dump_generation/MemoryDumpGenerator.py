import sys
import os
from gzip import GzipFile
from time import sleep
from uuid import uuid4
from zipfile import ZipFile
from zipfile import is_zipfile
import logging
import subprocess
import tempfile
import shutil

from VirtualBox import VirtualBox
from util.IsoImageCreator import IsoImageCreator
from util import utils


class MemoryDumpGenerator(object):
    """ Class used to generate memory test_data with the given
        vm settings and different samples.

        Keyword arguments:
        vm_settings -- a dict containing the settings for the vm
        silent -- whether to print log messages
    """

    defaults = {
        'name': '',
        'time': 120,
        'user': 'Max',
        'password': 'Power',
        'mountSample': False,
        'startDelay': 2,
        'guestDestDir': 'C:\\',
        'showBox': False
    }
    zip_password = 'infected'
    temp_folder = '/dev/shm'

    def __init__(self, vm_settings, silent=False, overwrite=False, notify=False, no_autorun=False):
        self.settings = MemoryDumpGenerator.defaults.copy()
        self.settings.update(vm_settings)
        self.guestDestFile = self.settings['guestDestDir'] + "\\" + str(uuid4())
        self.silent = silent
        self.vb = None
        self.iso = None
        self.iso_created = False
        self.overwrite = overwrite
        self.notify = notify
        self.no_autorun = no_autorun

    def generate(self, dumpPath, samplePath=None, compress=True):
        """ Generates a memory dump with the given sample
            at the given path.

            Keyword arguments:
            dumpPath -- where the dump is to be saved
            samplePath -- path to a zip or exe file (if any)
        """
        try:
            self.vb = self.__get_virtual_box()
            self.__start_virtual_box()
            if samplePath:
                sample, temp = self.__get_sample(samplePath)
                self.__infect_virtual_box(sample)
                if temp:
                    os.remove(sample)
                logging.info("waiting %r seconds to ensure malware executed. press enter to skip.",
                             self.settings['time'])
                self.interactive_sleep(self.settings['time'])
                if self.notify:
                    self.notify_send("Dumping in 10s")
                    self.interactive_sleep(10)
            self._save(dumpPath, compress)
        finally:
            if self.iso_created:
                self.vb.unmount_image()
                self.vb.delete_image(self.iso)
        self.vb.stop()

    @staticmethod
    def interactive_sleep(seconds):
        utils.clear_stdin()
        for i in xrange(seconds):
            if utils.enter_pressed():
                logging.info("enter pressed. continuing")
                return
            sleep(1)

    @staticmethod
    def notify_send(summary="", body=""):
        try:
            subprocess.check_call(["notify-send", summary, body])
        except OSError as e:
            logging.error("Error %r. Continuing." % e.message)

    def _save(self, path, compress=True):
        """ Intern method which saves the memory dump.
            TODO: look if Virtualbox finally implemented compression

            Keyword arguments:
            path -- where the dump is to be saved
            compress -- whether to compress the dump
        """

        if self.overwrite and os.path.exists(path):
            os.remove(path)

        if compress:
            rawPath = self.__get_temp_path()
            self.vb.dump(rawPath)
            self.compress(rawPath, path)
            os.remove(rawPath)
        else:
            self.vb.dump(path)

    def compress(self, input_file, output_file):
        logging.info("compressing %r to %r", input_file, output_file)
        with open(input_file, 'rb') as f_in:
            raw = f_in.read()
        with GzipFile(output_file, 'wb', compresslevel=1) as f_out:
            f_out.write(raw)

    def __infect_virtual_box(self, sample):
        """ Intern method which executes or mounts the given sample.

            Keyword arguments:
            sample -- path to the sample file
        """
        logging.info("infecting vm")
        if self.is_iso(sample):
            self.iso = self.infect_with_image(sample)
        elif self.settings['mountSample']:
            image_creator = IsoImageCreator(no_autorun=self.no_autorun)
            image_path = image_creator.create_image(sample)
            self.iso = self.vb.mount_image(image_path)
            self.iso_created = True
        else:
            self.vb.copy_to_guest(sample, self.guestDestFile)
            self.vb.execute(self.guestDestFile)

    def infect_with_image(self, sample):
        with tempfile.NamedTemporaryFile(suffix=".iso") as tmp_file:
            shutil.copyfile(sample, tmp_file.name)
            return self.vb.mount_image(tmp_file.name)

    @staticmethod
    def is_iso(sample):
        with open(sample) as f:
            f.seek(0x8001)
            return f.read(2) == "CD"

    def __start_virtual_box(self):
        """ Intern method which starts and resets the virtual box. """
        if self.vb.is_running():
            self.vb.stop()
        self.vb.reset()
        self.vb.start()
        logging.info("waiting %r seconds to ensure VM started", self.settings['startDelay'])
        sleep(self.settings['startDelay'])

    def __get_virtual_box(self):
        """ Intern method which returnes the virtual box. """
        return VirtualBox(
            self.settings['name'],
            self.settings['user'],
            self.settings['password'],
            gui=self.settings['showBox'])

    def __get_sample(self, path):
        """ Intern method which unzips the sample if zipped. """
        if path.endswith('.exe') or not is_zipfile(path):
            return path, False
        logging.info("sample is zipped. extracting.")
        extractionPath = self.__get_temp_path()
        password = MemoryDumpGenerator.zip_password
        with ZipFile(path, 'r') as archive:
            raw = archive.read(archive.namelist()[0], password)
        with open(extractionPath, 'wb') as filehandle:
            filehandle.write(raw)
        return extractionPath, True

    def __get_temp_path(self):
        return os.path.join(MemoryDumpGenerator.temp_folder, str(uuid4()))


def generate_dump(sample, output_file, vm_settings, compress, overwrite, notify):
    logging.info("output_file: %r", output_file)
    generator = MemoryDumpGenerator(vm_settings=vm_settings, overwrite=overwrite, notify=notify)
    generator.generate(dumpPath=output_file, samplePath=sample, compress=compress)


def generate_dumps(samples, output_dir, vm_settings, compress, overwrite, notify):
    generator = MemoryDumpGenerator(vm_settings=vm_settings, overwrite=overwrite, notify=notify)
    for sample in samples:
        output_file = os.path.join(output_dir, sample)
        generator.generate(dumpPath=output_file, samplePath=sample, compress=compress)


def parse_args():
    from util.CommandLineParser import CommandLineParser
    parser = CommandLineParser(sys.argv[1:])
    return parser.parse()


def init(args):
    format_ = "%(asctime)s;%(levelname)s;%(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"
    level = logging.WARNING if args['silent'] else logging.INFO
    logging.basicConfig(level=level, format=format_, datefmt=date_format)


def main():
    args = parse_args()

    init(args)

    vm_settings = {
        'name': args['vmname'],
        'time': args['time'],
        'user': args['username'],
        'password': args['password'],
        'mountSample': args['installmethod'] == 'iso',
        'showBox': args['showvbox']
    }

    if os.path.isdir(args['samples']):
        samples = [os.path.join(args['samples'], filename) for filename in os.listdir(args['samples'])]
        generate_dumps(samples, args['outputpath'], vm_settings, args['compress'], args['overwrite'], args['notify'])
    else:
        sample = args['samples']
        output_file = get_output_file(args, sample)
        generate_dump(sample, output_file, vm_settings, args['compress'], args['overwrite'], args['notify'])


def get_output_file(args, sample):
    sample_basename = os.path.basename(sample)
    if os.path.isdir(args["outputpath"]):
        output_file = os.path.join(args["outputpath"], sample_basename)
    else:
        output_file = args["outputpath"]
    return output_file


if __name__ == '__main__':
    main()
