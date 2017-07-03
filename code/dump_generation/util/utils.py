import sys
import logging
import platform
import tempfile
import contextlib
import shutil
import select

if platform.system() == 'Linux':
    tempfile_dir = '/dev/shm'
else:
    tempfile_dir = None


def getTempDir():
    tempdir = tempfile.mkdtemp(dir=tempfile_dir)
    logging.debug("Created temp dir: %r" % tempdir)
    return tempdir


@contextlib.contextmanager
def temporaryDirectory(*args, **kwargs):
    d = tempfile.mkdtemp(*args, dir=tempfile_dir, **kwargs)
    try:
        yield d
    finally:
        shutil.rmtree(d)


def clear_stdin():
    while select.select([sys.stdin], [], [], 0)[0]:
        sys.stdin.read(1)


def enter_pressed():
    return bool(select.select([sys.stdin], [], [], 0)[0])
