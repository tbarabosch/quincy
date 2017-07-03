# statically loaded libraries have a load count of 0x0000ffff (-1), dynamically loaded libraries have one that is
# greater 1. Check the following posts:
# - http://stackoverflow.com/questions/22855932/is-0x0000ffff-the-default-load-count-of-a-dll-in-windows
# - http://www.securityxploded.com/dllrefcount.php

def scan(Scanner):
    res = {}
    for process in Scanner.processes:
        process_res = {}
        for vad in process.VADs:
            name = hex(vad.Start)[:-1] + "_" + hex(vad.End)[:-1]
            module = get_module(process, vad)
            if module:
                if module.LoadCount == 0x0000ffff:
                    process_res[name] = 0
                else:
                    process_res[name] = 1
            else:
                process_res[name] = 0
        res[str(process.Id)] = process_res
    return res

def get_module(process, vad):
    for module in process.Modules:
        if vad in module:
            return module
    return None