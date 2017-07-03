from pefile import PE

def scan(Scanner):
    output = {}
    for process in Scanner.processes:
        output[str(process.Id)] = check_vads(process)
    return output


def check_vads(process):
    res = {}
    for vad in process.VADs:
        name = hex(vad.Start)[:-1] + "_" + hex(vad.End)[:-1]
        res[name] = check_type(vad)
    return res


def check_type(vad):
    try:
        p = PE(data=vad.read())
        if p.FILE_HEADER.IMAGE_FILE_DLL:
            return 2
        else:
            return 1
    except Exception as e:
        return 0
