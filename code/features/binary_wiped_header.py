def scan(Scanner):
    output = {}
    for process in Scanner.processes:
        output[str(process.Id)] = check_headers(process)
    return output


def check_headers(process):
    res = {}
    for vad in process.VADs:
        name = hex(vad.Start)[:-1] + "_" + hex(vad.End)[:-1]
        res[name] = header_wiped(vad)
    return res


def header_wiped(vad):
    data = vad.read()
    if len(data) > 0x1002:
        if data[:0x1000].count(chr(0)) == 0x1000:
            if data[0x1000:0x1002] == "\x55\x8B":
                return 1
    return 0
