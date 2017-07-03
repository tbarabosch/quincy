import logging

def scan(Scanner):
    res = {}
    for process in Scanner.processes:
        logging.debug("Scanning process %r (%r)", process.Id, process.Name)
        process_res = {}
        for vad in process.VADs:
            name = hex(vad.Start)[:-1] + "_" + hex(vad.End)[:-1]
            process_res[name] = is_in_module(process, vad)
        res[str(process.Id)] = process_res
    return res

def is_in_module(process, vad):
    return int(any(vad in module for module in process.Modules))
