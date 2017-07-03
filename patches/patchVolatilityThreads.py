import sys
import os
import subprocess

def locate_threads_file():
    return subprocess.check_output('locate memory_threads.py | grep "python2.7/.*packages.*/volatility/plugins/malware/memory_threads.py\$"', shell=True)[:-1]

if os.geteuid() != 0:
    print "You have to run this script as root."
    sys.exit(-1)
try:
    threads_file = locate_threads_file()
except subprocess.CalledProcessError:
    print "Updating locate db..."
    subprocess.call('updatedb')
    threads_file = locate_threads_file()

try:
    print "Trying to remove compiled file 'threads.pyc'"
    os.remove(threads_file + "c")
except OSError as e:
    print "WARNING: Couldn't remove 'threads.pyc': %r" % e.message

with open(threads_file, 'r+') as f:
    s = f.read()
    before = '# Check the flag which indicates whether Win32StartAddress is valid\n\
            if thread.SameThreadApcFlags & 1:'
    after = '# Check the flag which indicates whether Win32StartAddress is valid\n\
            # PATCHED: Skip this check, the flag does not indicate correctly\n\
            # if thread.SameThreadApcFlags & 1:\n\
            if True:'
    if after in s:
        print "Patching failed: Patch already applied."
        sys.exit(-1)

    if not before in s:
        print "Patching failed: Couldn't find string in file."
        sys.exit(-1)

    s = s.replace(before, after)
    f.seek(0)
    f.truncate()
    f.seek(0)
    f.write(s)
    print "Success."
