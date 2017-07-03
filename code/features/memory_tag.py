def scan(Scanner):
    output = {}
    for process in Scanner.processes:
        process_res = {}
        for vad in process.VADs:
            name = hex(vad.Start)[:-1] + "_" + hex(vad.End)[:-1]
            process_res[name] = int(vad.Tag == 'VadS')
        output[str(process.Id)] = process_res
    return output
