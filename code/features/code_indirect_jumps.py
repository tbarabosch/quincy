import re

RE_DIRECT_JUMP = re.compile(r'\xe9...\x00')
# 0:  e9 fc ff 3f 00          jmp    400001 <_main+0x400001>

RE_INDIRECT_JUMP = re.compile(r'\xff\xe0|\xff\xe3|\xff\xe1|\xff\xe2|\xff\xe6|\xff\xe7')
# 0:  ff e0                   jmp    eax
# 2:  ff e3                   jmp    ebx
# 4:  ff e1                   jmp    ecx
# 6:  ff e2                   jmp    edx
# 8:  ff e6                   jmp    esi
# a:  ff e7                   jmp    edi

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
        indirect_jmps = len(re.findall(RE_INDIRECT_JUMP, data))
        direct_jmps = len(re.findall(RE_DIRECT_JUMP, data))
        if (indirect_jmps + direct_jmps) > 0:
            ratio_jmps = float(indirect_jmps) / float(indirect_jmps + direct_jmps) * 100.0
        else:
            ratio_jmps = 0.0
        res[name] = float(format(ratio_jmps, '.2f'))
    return res
