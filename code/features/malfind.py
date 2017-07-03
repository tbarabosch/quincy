from subprocess import check_output
from re import compile
from QuincyConfig import volatility_path

# sample output of malfind
# Process: winlogon.exe Pid: 592 Address: 0x78a30000
pattern = compile('Pid: ([0-9]+) Address: 0x([0-9a-f]+)')

def scan(Scanner):
    cmd = ['python', volatility_path, 'malfind', '--profile=%s' % Scanner.profile, '--filename=%s' % Scanner.path]
    output = check_output(cmd)
    matches = list(pattern.finditer(output))

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
            if int(match.group(1)) == pid and int(match.group(2), 16) == vad.Start:
                return True
    return False