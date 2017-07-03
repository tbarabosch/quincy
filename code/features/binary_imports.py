from pefile import PE

def scan(Scanner):
    output = {}
    for process in Scanner.processes:
        output[str(process.Id)] = get_imports(process)
    return output


def get_imports(process):
    res = {}
    for vad in process.VADs:
        name = hex(vad.Start)[:-1] + "_" + hex(vad.End)[:-1]
        res[name] = get_imports_of_vad(vad.read())
    return res


def get_imports_of_vad(data):
    try:
        pe = PE(data=data)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            res = 1
        else:
            res = 0
        return res
    except Exception as e:
        return 0
