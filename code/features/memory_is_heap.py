import volatility.obj as obj

def scan(Scanner):
    output = {}
    for process in Scanner.processes:
        output[str(process.Id)] = check_heaps(process)
    return output


def check_heaps(process):
    res = {}
    for vad in process.VADs:
        name = hex(vad.Start)[:-1] + "_" + hex(vad.End)[:-1]
        res[name] = int(is_address_heap(process, vad.Start))
    return res


def is_address_heap(process, address):
    if process.Peb:
        if process.Peb.ProcessHeaps:
            heaps = obj.Object("Array", targetType="Pointer", count=process.Peb.NumberOfHeaps.v(),
                               vm=process.VirtualMemory, offset=process.Peb.ProcessHeaps)
        elif process.Peb.ProcessHeap:
            heaps = [process.Peb.ProcessHeap]
        else:
            return False
        if heaps and address in heaps:
            return True
    return False
