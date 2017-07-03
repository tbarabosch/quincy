import yara
import os

def scan(Scanner):
    p = os.path.join(os.path.split(os.path.realpath(__file__))[0], 'yara/hooks.yar')
    rules = yara.compile(filepath=p)
    output = {}
    for process in Scanner.processes:
        output[str(process.Id)] = scan_vads(process, rules)
    return output

def scan_vads(process, rules):
    res = {}
    for vad in process.VADs:
        name = hex(vad.Start)[:-1] + "_" + hex(vad.End)[:-1]
        data = vad.read()
        matches = rules.match(data=data)
        res[name] = int(len(matches) > 0)
    return res

