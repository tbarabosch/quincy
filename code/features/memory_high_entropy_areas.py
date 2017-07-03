from entropy import shannon_entropy

SIZE_OF_AREA = 0x1000
HIGH_ENTROPY = 6.5 / 8.0

def scan(Scanner):
    output = {}
    for process in Scanner.processes:
        output[str(process.Id)] = check_vads(process)
    return output


def check_vads(process):
    res = {}
    for vad in process.VADs:
        name = hex(vad.Start)[:-1] + "_" + hex(vad.End)[:-1]
        res[name] = compute_entropy_for_areas(vad.read())
    return res

def entropy(s):
    return shannon_entropy(s)

def compute_entropy_for_areas(data):
    number_of_areas = len(data) / SIZE_OF_AREA + 1
    high_entropy_areas = 0
    curPos = 0
    while curPos < len(data) + SIZE_OF_AREA:
        entropy_of_area = entropy(data[curPos:curPos+SIZE_OF_AREA])
        if entropy_of_area > HIGH_ENTROPY:
            high_entropy_areas += 1
        curPos += SIZE_OF_AREA

    # final area
    entropy_of_area = entropy(data[curPos:])
    if entropy_of_area > HIGH_ENTROPY:
        high_entropy_areas += 1

    res = (float(high_entropy_areas) / float(number_of_areas)) * 100.0
    return float(format(res, '.2f'))