from pefile import PE

def scan(Scanner):
    output = {}
    for process in Scanner.processes:
        output[str(process.Id)] = get_exports(process)
    return output


def get_exports(process):
    res = {}
    for vad in process.VADs:
        name = hex(vad.Start)[:-1] + "_" + hex(vad.End)[:-1]
        res[name] = get_exports_of_vad(vad)
    return res


def get_exports_of_vad(vad):
    try:
        pe = PE(data=vad.read())
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            return 1
        else:
            return 0
    except Exception as e:
        return 0
