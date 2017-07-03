import os, sys
import gzip
import tempfile
import logging
import platform
import select
from hashlib import sha256
from contextlib import contextmanager

def dec2Hex(dec):
    return None if dec is None else ("0x%.8X" % dec).lower()

def is_gzip(path):
    with open(path, 'rb') as fh:
        return fh.read(2) == '\x1f\x8b'

def readPath(self, directory):
    paths = []
    for (root, dirs, files) in os.walk(directory):
        for filename in files:
            path = os.path.join(root, filename)
            paths.append(path)
    return paths

def getHash(data):
    hasher = sha256()
    raw = data
    if isinstance(data, file):
        raw = data.read()
    hasher.update(raw)
    return hasher.hexdigest()

def getTempDir():
    if platform.system() == 'Linux':
        tempdir = tempfile.mkdtemp(dir='/dev/shm')
    else:
        tempdir = tempfile.mkdtemp()
    logging.debug("Created temp dir: %r" % tempdir)
    return tempdir

@contextmanager
def silent():
    with open(os.devnull, "w") as devnull:
        old_stdout = sys.stdout
        sys.stdout = devnull
        try:
            yield
        finally:
            sys.stdout = old_stdout


def tryExtractDump(path, profile):
    # ToDo: check if space available on /dev/shm, raise error if not
    if is_gzip(path):
        extractionpath = os.path.join(getTempDir(), profile + '_' + os.path.basename(path) + '.tmp')
        archive = gzip.open(path)
        with open(extractionpath, 'wb') as fh:
            for chunk in read_in_chunks(archive):
                fh.write(chunk)
        archive.close()
        return extractionpath


def read_in_chunks(file_object, chunk_size=4 * 1024):
    while True:
        data = file_object.read(chunk_size)
        if not data:
            break
        yield data

@contextmanager
def extract_if_packed(input_path):
    with tempfile.NamedTemporaryFile(dir=getTempDir()) as f:
        output_path = f.name
        try:
            logging.debug("Extracting %r to %r" % (input_path, output_path))
            with gzip.open(input_path) as f_in:
                with open(output_path, 'wb') as f_out:
                    f_out.write(f_in.read())
        except IOError:
            logging.debug("%r is not a gzipped file. Copying to %r" % (input_path, output_path))
            with open(input_path) as f_in:
                with open(output_path, 'wb') as f_out:
                    f_out.write(f_in.read())
        yield output_path


def clear_stdin():
    while select.select([sys.stdin], [], [], 0)[0]:
        sys.stdin.read(1)


def enter_pressed():
    return bool(select.select([sys.stdin], [], [], 0)[0])


def set_up_logging(verbose):
    if verbose:
        logging.basicConfig(level=logging.DEBUG, format='%(levelname)-5s %(message)s')
    else:
        logging.basicConfig(level=logging.INFO, format='%(levelname)-5s %(message)s')

class MemoryDump(object):
    def __init__(self, path):
        self.extractionpath = None
        self.path = path

    def __enter__(self):
        if not is_gzip(self.path):
            return self.path
        else:
            self.extractionpath = os.path.join(getTempDir(), os.path.basename(self.path) + '.tmp')
            archive = gzip.open(self.path)
            with open(self.extractionpath, 'wb') as fh:
                for chunk in read_in_chunks(archive):
                    fh.write(chunk)
            return self.extractionpath

    def __exit__(self, type, value, tb):
        if self.extractionpath:
            os.remove(self.extractionpath)