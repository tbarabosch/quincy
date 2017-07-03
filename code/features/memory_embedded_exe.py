from pefile import PE
import re

RE_MAGIC = re.compile("\x5a\x4d")

def scan(Scanner):
    output = {}
    for process in Scanner.processes:
        output[str(process.Id)] = check_vads(process)
    return output


def check_vads(process):
    res = {}
    for vad in process.VADs:
        name = hex(vad.Start)[:-1] + "_" + hex(vad.End)[:-1]
        res[name] = check_for_embedded_bins(vad)
    return res


def check_for_embedded_bins(vad):
    # Check for MZ and PE magic after 1000 bytes...
    data = vad.read()[0x1000:]
    matches = re.finditer(RE_MAGIC, data)

    for match in matches:
        try:
            p = PE(data=data[match.start():])
            if p.OPTIONAL_HEADER.ImageBase:
                return 1
            else:
                pass
        except Exception as e:
            continue

    return 0