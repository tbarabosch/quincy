import re

apiRegex = re.compile(r'Close|Copy|Create|Delete|Find|Open|Set')

def scan(Scanner):
    output = {}
    for process in Scanner.processes:
        output[str(process.Id)] = check_vads(process)
    return output

def check_vads(process):
    res = {}
    for vad in process.VADs:
        name = hex(vad.Start)[:-1] + "_" + hex(vad.End)[:-1]
        if not is_in_module(process, vad):
            data = vad.read()
            res[name] = contains_api_strings(data)
        else:
            res[name] = 0
    return res

def contains_api_strings(data):
    res = re.findall(apiRegex, data)
    return int(len(res) > 0)

def is_in_module(process, vad):
    return int(any(vad in module for module in process.Modules))