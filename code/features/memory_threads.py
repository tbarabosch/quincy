def scan(Scanner):
    output = {}
    for process in Scanner.processes:
        process_res = {}
        threads = [thread for thread in Scanner.threads if thread.Pid == process.Id]
        for vad in process.VADs:
            threads_in_vad = 0
            for thread in threads:
                if vad.contains(thread.Start):
                    threads_in_vad += 1
            name = hex(vad.Start)[:-1] + "_" + hex(vad.End)[:-1]
            if threads_in_vad > 0:
                process_res[name] = 1
            else:
                process_res[name] = 0
        output[str(process.Id)] = process_res
    return output
