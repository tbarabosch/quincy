import re

RE_DIRECT_CALL = re.compile(r'\xe8...\x00')
# 0:  e8 fc ff 3f 00          call   400001 <_main+0x400001>

RE_INDIRECT_CALL = re.compile(r'\xff\xd0|\xff\xd3|\xff\xd1|\xff\xd2|\xff\xd6|\xff\xd7')
# 0:  ff d0                   call   eax
# 2:  ff d3                   call   ebx
# 4:  ff d1                   call   ecx
# 6:  ff d2                   call   edx
# 8:  ff d6                   call   esi
# a:  ff d7                   call   edi

def scan(Scanner):
    output = {}
    for process in Scanner.processes:
        output[str(process.Id)] = scan_vads(process)
    return output

def scan_vads(process):
    res = {}
    for vad in process.VADs:
        name = hex(vad.Start)[:-1] + "_" + hex(vad.End)[:-1]
        data = vad.read()
        indirect_calls = len(re.findall(RE_INDIRECT_CALL, data))
        direct_calls = len(re.findall(RE_DIRECT_CALL, data))
        if (indirect_calls + direct_calls) > 0:
            ratio_calls = float(indirect_calls) / float(indirect_calls + direct_calls) * 100.0
        else:
            ratio_calls = 0.0
        res[name] = float(format(ratio_calls, '.2f'))
    return res
