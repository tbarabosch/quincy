# this file parses the output of hollowfind. For the sake of simplicity, we modified the output of hollowfind as follows:
# example output windows 7
# !1/2,lsm.exe,440,0xba0000
# !SUS,lsm.exe,440,0x77ba0000
# !1/2,smss.exe,216,0x48050000
# !SUS,smss.exe,216,0x77ba0000
# !1/2,wmpnetwk.exe,872,0x230000
# !SUS,wmpnetwk.exe,872,0x460000
# !SUS,wmpnetwk.exe,872,0x6d870000
import logging

from subprocess import check_output
from QuincyConfig import volatility_path

def scan(Scanner):
    try:
        cmd = ['python', volatility_path, 'hollowfind', '--profile=%s' % Scanner.profile, '--filename=%s' % Scanner.path]
        o = check_output(cmd)
        lines = o.splitlines()
    except:
        logging.error("Hollowfind crashed.")
        lines = []

    matches = []
    for l in lines:
        if l.startswith("!"):
            print l
            splitted_line = l.split(",")
            matches.append((splitted_line[2], splitted_line[3]))

    output = {}
    for process in Scanner.processes:
        output[str(process.Id)] = get_infections(process, matches)
    return output

def get_infections(process, matches):
    res = {}
    for vad in process.VADs:
        name = hex(vad.Start)[:-1] + "_" + hex(vad.End)[:-1]
        if is_infected(matches, vad, process.Id):
            res[name] = 0
        else:
            res[name] = 1
    return res

def is_infected(matches, vad, pid):
    if len(matches) > 0:
        for match in matches:
            if int(match[0]) == pid and int(match[1], 16) == vad.Start:
                return True
    return False