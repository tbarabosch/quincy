from pefile import PE

def scan(Scanner):
    output = {}
    for process in Scanner.processes:
        output[str(process.Id)] = check_headers(process)
    return output


def check_headers(process):
    res = {}
    for vad in process.VADs:
        name = hex(vad.Start)[:-1] + "_" + hex(vad.End)[:-1]
        res[name] = has_header(vad)
    return res


def has_header(vad):
    try:
        PE(data=vad.read())
        return 1
    except Exception as e:
        return 0
