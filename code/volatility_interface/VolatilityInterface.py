import logging

import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.addrspace as addrspace
import volatility.utils as utils
import volatility.plugins.vadinfo as vadinfo
import volatility.plugins.malware.threads as threads
import volatility.plugins.malware.psxview as psxview
from volatility.win32.tasks import pslist

logging.getLogger('volatility.utils').setLevel(logging.ERROR)
logging.getLogger('volatility.obj').setLevel(logging.ERROR)
logging.getLogger('volatility.win32.rawreg').setLevel(logging.ERROR)


class Thread():
    """ Class representing a thread in a dump. """

    def __init__(self, thread, memory):
        self.CreateTime = thread.CreateTime
        self.Offset = thread.obj_offset
        self.Tid = thread.Cid.UniqueThread
        self.Pid = thread.Cid.UniqueProcess
        self.Memory = memory
        self.State = thread.Tcb.State
        self.Priority = thread.Tcb.Priority
        self.Start = thread.Win32StartAddress
        self.Register = thread.Tcb.TrapFrame.dereference_as("_KTRAP_FRAME")

    def __str__(self):
        return "Thread @ %s Tid: %d Pid: %d Start: %s (%s)" % (self.Offset,
                                                               self.Tid, self.Pid, self.Start, self.Register.Eip)


class VAD():
    """ Class representing a single VAD in a dump. """

    def __init__(self, vad, physicalMemory, virtualMemory):
        self.Offset = vad.obj_offset
        self.Start = vad.Start
        self.End = vad.End
        self.Tag = vad.Tag
        self.Flags = set()
        self.VadFlags = vad.VadFlags
        try:
            self.ControlFlags = vad.ControlArea.u.Flags
        except AttributeError:
            self.ControlFlags = None
        self.PhysicalMemory = physicalMemory
        self.VirtualMemory = virtualMemory
        if hasattr(vad, 'u'):
            infostring = vadinfo.PROTECT_FLAGS[vad.u.VadFlags.Protection.v()]
        else:
            infostring = ''
        try:
            self.File = str(vad.FileObject.FileName)
        except AttributeError:
            self.File = None
        if "EXECUTE" in infostring:
            self.Flags.update({"Execute", "Read"})
        if "WRITE" in infostring:
            self.Flags.update({"Write", "Read"})
        if "READ" in infostring:
            self.Flags.update({"Read"})
        if "NOACCESS" in infostring:
            self.Flags.update({"NoAccess"})

    def contains(self, address):
        """ Returns true if the vad contains the given address. """
        return self.Start <= address <= self.End

    def __str__(self):
        return "VAD @ %s Start: %s End: %s %s %s" % (hex(self.Offset),
                                                     hex(self.Start), hex(self.End), self.Flags, self.File)

    def read(self, offset=0, length=None):
        """ A method which reads the memory of a vad at the given offset.

            Keyword arguments:
            offset -- offset inside the VAD to read from
            length -- length of the test_data read
        """
        if not length:
            length = self.End - self.Start
        return self.VirtualMemory.zread(self.Start + offset, length)


class Process():
    """ Class representing a logical process in a dump. """

    def __init__(self, eprocess, memory):
        self.Name = str(eprocess.ImageFileName)
        self.Id = int(eprocess.UniqueProcessId)
        self.Parent = eprocess.InheritedFromUniqueProcessId
        self.VirtualMemory = eprocess.get_process_address_space()
        self.PhysicalMemory = memory
        self.Offset = eprocess.obj_offset
        self.ImageBaseAddress = eprocess.Peb.ImageBaseAddress
        self.Peb = eprocess.Peb
        self.Modules = self.getModules(eprocess)
        self.SectionBaseAddress = eprocess.SectionBaseAddress
        vads = []
        for vad in eprocess.VadRoot.traverse():
            vads.append(VAD(vad, memory, self.VirtualMemory))
        self.VADs = tuple(vads)

    @staticmethod
    def getModules(eprocess):
        modules = list()
        for module in eprocess.get_load_modules():
            modules.append(Module(module, eprocess))
        return modules

    def getVAD(self, base):
        """ Get the VAD representing a certain offset in the process space.

            Keyword arguments:
            base -- the offset inside the virtual address space
        """
        for vad in self.VADs:
            if base == vad.Start:
                return vad

    def read(self, base, length):
        """ Reads test_data from the virtual memory range of the process.

            Keyword arguments:
            base -- the offset in the adress space to read from
            length -- the amout of bytes to be read
        """
        data = self.VirtualMemory.zread(base, length)
        if not len(data) == length:
            return self.PhysicalMemory.zread(base, length)
        return data

    def __str__(self):
        return "Process #%d (%d): %s (%d vads)" % (self.Id,
                                                   self.Parent, self.Name, len(self.VADs))


class Module(object):
    def __init__(self, module, eprocess):
        self.Offset = module.obj_vm.vtop(
            module.obj_offset)  # TODO: Check if this works with all commands (modules, ldrmodules, dlllist, ...)
        self.PID = int(eprocess.UniqueProcessId)
        self.BaseDllName = str(module.BaseDllName or '')
        self.DllBase = int(module.DllBase)
        self.Start = self.DllBase
        self.SizeOfImage = int(module.SizeOfImage)
        self.Size = self.SizeOfImage
        self.End = self.Start + self.Size
        self.FullDllName = str(module.FullDllName or '')
        self.LoadCount = int(module.LoadCount)

    def __contains__(self, vad):
        return self.Start <= vad.Start <= vad.End <= self.End


class VolatilityInterface():
    """ A class representing a memorydump progressed by Volatility.

        Keyword arguments:
        path -- the path to the dump to be analyzed
        profile -- the profile to parse the memory dump with (default 'WinXPSP2x86')
    """

    def __init__(self, path, profile='WinXPSP2x86'):
        self.config = conf.ConfObject()
        registry.PluginImporter()
        registry.register_global_options(self.config, commands.Command)
        registry.register_global_options(self.config, addrspace.BaseAddressSpace)
        # self.config.parse_options()
        self.config.PROFILE = profile
        self.config.LOCATION = "file://" + path
        self.Memory = utils.load_as(self.config)
        self.Processes = self.__getProcesses()
        self.Threads = self.__getThreads()

    def __getProcesses(self, scan=False):
        """ Intern method to scan the memory for processes. """
        if not scan:
            plist = pslist(self.Memory)
            p = list(plist)
        else:
            _raw = []
            for offset, process, _ in psxview.PsXview(self.config).calculate():
                _raw.append(process)
            p = _raw
        return [Process(process, self.Memory) for process in p]

    def __getThreads(self):
        """ Intern mthod to scan the memory for threads. """
        p = threads.Threads(self.config)
        return [Thread(thread[0], thread[1]) for thread in p.calculate()]
