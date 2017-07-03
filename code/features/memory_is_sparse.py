def scan(Scanner):
    output = {}
    for process in Scanner.processes:
        output[str(process.Id)] = check_vads(process)
    return output


def check_vads(process):
    res = {}
    for vad in process.VADs:
        name = hex(vad.Start)[:-1] + "_" + hex(vad.End)[:-1]
        res[name] = get_sparseness(vad)
    return res


def get_sparseness(vad):
    data = vad.read()
    return float(format(float(data.count(chr(0))) / float(len(data)), '.2f'))
