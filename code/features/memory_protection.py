def scan(Scanner):
    return RwxVads(Scanner.processes).scan()

class RwxVads():
    def __init__(self, processes):
        self.processes = processes
        self.rwxvads_by_process = {}

    def scan(self):
        for process in self.processes:
            self.rwxvads_by_process[str(process.Id)] = self.scan_process(process)
        return self.rwxvads_by_process

    def scan_process(self, process):
        rwxvads = {}
        for vad in process.VADs:
            res = 0
            if 'NoAccess' in set(vad.Flags):
                res += 1000
            if 'Execute' in set(vad.Flags):
                res += 100
            if 'Read' in set(vad.Flags):
                res += 10
            if 'Write' in set(vad.Flags):
                res += 1
            name = hex(vad.Start)[:-1] + "_" + hex(vad.End)[:-1]
            rwxvads[name] = res
        return rwxvads
