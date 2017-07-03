import os
import logging
from time import sleep
from vboxapi import VirtualBoxManager
from vboxapi.VirtualBox_constants import VirtualBoxReflectionInfo

vbox_constants = VirtualBoxReflectionInfo(None)
storage_bus_types = vbox_constants.all_values('StorageBus')
machine_states = vbox_constants.all_values('MachineState')

# A dict mappint the numbers from MachineState returned by virtual box to a human readable version
MACHINE_STATES = {0: 'Null', 1: 'PoweredOff', 2: 'Saved', 3: 'Teleported', 4: 'Aborted', 5: 'Running', 6: 'Paused',
                  7: 'Stuck', 8: 'Teleporting', 9: 'LiveSnapshotting', 10: 'Starting', 11: 'Stopping', 12: 'Saving',
                  13: 'Restoring', 14: 'TeleportingPausedVM', 15: 'TeleportingIn', 16: 'FaultTolerantSyncing',
                  17: 'DeletingSnapshotOnline', 18: 'DeletingSnapshotPaused', 19: 'RestoringSnapshot',
                  20: 'DeletingSnapshot',
                  21: 'SettingUp'}


# The type of exception used by the VirtualBox class
class VBoxException(Exception):
    pass


class VirtualBox:
    """A class representing a VirtualBox machine.

    Keyword arguments:
    vmname -- name of the virtual machine to be used
    user -- user to login as on the virtual box
    password -- password of the given user (default '')
    gui -- whenever virtualbox should show a gui (default False)
    silent -- whenever statusmessages should be hidden (default False)
    """

    mgr = VirtualBoxManager(None, None)
    mach = None
    session = None
    guestsession = None

    def __init__(self, vmname, user, password='', gui=False):
        self.vmname = vmname
        logging.info("initializing VirtualBox machine: " + vmname)
        self.user = user
        self.password = password
        self.operation_mode = 'gui' if gui else 'headless'
        self.mach = self.mgr.vbox.findMachine(self.vmname)
        self.os = 'windows' if 'windows' in self.mach.OSTypeId.lower() else 'linux'
        # If the machine is already running, we need to stop it first
        if self.is_running():
            self.session = self.mgr.mgr.getSessionObject(self.mgr.vbox)
            self.lock()
            self.stop()
            sleep(2)
            self.mach = self.mgr.vbox.findMachine(self.vmname)

        self.session = self.mgr.mgr.getSessionObject(self.mgr.vbox)

    def get_name_of_storage_controller(self, machine):
        controllers = self.mgr.getArray(machine, "storageControllers")

        for c in controllers:
            if c.bus in [storage_bus_types['IDE'], storage_bus_types['SATA']]:
                return c.name
        raise VBoxException("no suitable IDE or SATA controller found. Please check your machine settings")

    def __get_guest_session(self):
        if not self.guestsession:
            raise VBoxException("vm is not running")
        return self.guestsession

    def __check(self):
        if not self.is_running():
            raise VBoxException("vm is not running")

    def join_path(self, *argv):
        """Joins a path for the guest machine.

        Keyword arguments:
        *argv -- strings to be joined to a path.
        """
        path = argv[0]
        sep = '\\' if self.os == 'windows' else '/'
        for i, arg in enumerate(argv[1:]):
            path += '%s%s' % (sep, arg)
        return path

    def is_running(self):
        """Returnes True if the guest machine is running."""
        return self.mach.state == 5

    def take_screenshot(self, path):
        """Takes a screenshot on the guest machine.

        Keyword arguments:
        path -- path on the host machine where the screenshot should be saved.
        """
        cmd = "/usr/bin/VBoxManage controlvm " + self.vmname + " screenshotpng " + os.path.join(path, "screenshot.png")
        logging.info("Taking screen shot.")
        os.system(cmd)

    def machineState(self):
        """Returnes a string describing the machine state."""
        return MACHINE_STATES[self.mach.state]

    def lock(self):
        """Locks a session on the guest machine. """
        self.session = self.mgr.openMachineSession(self.mach)
        self.mach = self.session.machine

    def unlock(self):
        """Unlocks a session on the guest machine.

        Keyword arguments:
        session -- the session to be unlocked
        """
        self.session.unlockMachine()

    def start(self, timeout=30):
        """Starts the viurtual machine and creates a session."""
        logging.info("starting vm")
        self.mach = self.mgr.vbox.findMachine(self.vmname)
        self.session = self.mgr.getSessionObject(self.mach)
        progress = self.mach.launchVMProcess(self.session, self.operation_mode, "")
        progress.waitForCompletion(-1)
        # FIXME: Fails in virtualbox 4.3 with "The session is not locked (session state: Unlocked)", works in virtualbox 5.0
        guest = self.session.console.guest
        self.guestsession = guest.createSession(self.user, self.password, "", self.user)
        result = self.guestsession.waitFor(self.mgr.constants.GuestSessionWaitForFlag_Start, timeout * 1000)
        if result == self.mgr.constants.GuestSessionWaitResult_Timeout:
            raise VBoxException("A session for '%s' could not be created." % self.user)

    def stop(self):
        """Stops the virtual machine guest."""
        progress = self.session.console.powerDown()
        progress.waitForCompletion(-1)
        self.unlock()

    def reset(self):
        """Rolls the virtual machine back to its last snapshot."""
        logging.info("resetting vm")
        self.lock()
        progress = self.mach.restoreSnapshot(self.mach.currentSnapshot)
        # progress = self.session.console.restoreSnapshot(self.mach.currentSnapshot)
        progress.waitForCompletion(-1)
        self.unlock()

    def walk(self, top):
        """Pseudo implentation of os.walk for the virtual guest."""
        self.__check()
        guestSession = self.__get_guest_session()
        todo = [top]
        while todo:
            root = todo.pop()
            files = []
            directories = []
            directory = guestSession.directoryOpen(root, '', [self.mgr.constants.DirectoryOpenFlag_None])
            while True:
                try:
                    fileData = directory.read()
                    if fileData.type == self.mgr.constants.FsObjType_File:
                        files.append(fileData.name)
                    elif fileData.type == self.mgr.constants.FsObjType_Directory:
                        if fileData.name not in ['.', '..']:
                            directories.append(fileData.name)
                            todo.append(self.join_path(root, fileData.name))
                except Exception, e:  # TODO: too broad exception clause. Which exception do we want to catch here?
                    directory.close()
                    yield root, directories, files
                    break

    def dump(self, path, overwrite=False):
        """Dumps the memory of the guest machine to a file.

        Keyword arguments:
        outputPath -- folder on the host machine where the dump is saved
        filename -- the filename of the generated dump
        overwrite -- whenever to overwrite excisting test_data (default False)
        """
        self.__check()
        if not os.path.exists(os.path.dirname(path)):
            os.makedirs(os.path.dirname(path))
        debugger = self.session.console.debugger
        if not os.path.exists(path) or overwrite:
            if os.path.exists(path):
                os.remove(path)
            logging.info("dumping memory to %r", path)
            debugger.dumpGuestCore(path, "")
        else:
            raise VBoxException("dump file %r already exists" % path)

    def mount_image(self, path):
        """Mounts an iso-file as a virtual drive in the guest machine.

        Keyword arguments:
        path -- path of the iso file to be mounted.
        """
        self.__check()
        logging.info("mounting %r" % path)
        mutable_machine = self.session.machine
        controller_name = self.get_name_of_storage_controller(mutable_machine)
        iso = self.mgr.vbox.openMedium(path, self.mgr.constants.DeviceType_DVD, self.mgr.constants.AccessMode_ReadOnly,
                                       False)
        mutable_machine.mountMedium(controller_name, 1, 0, iso, True)
        mutable_machine.saveSettings()
        sleep(1)
        return iso

    def unmount_image(self):
        """Unmounts an iso-file in the guest machine.

        Keyword arguments:
        path -- path of the iso file to be mounted.
        """
        self.__check()
        logging.info("unmounting iso")
        mutable_machine = self.session.machine
        controller_name = self.get_name_of_storage_controller(mutable_machine)
        mutable_machine.unmountMedium(controller_name, 1, 0, True)
        mutable_machine.saveSettings()

    @staticmethod
    def delete_image(medium):
        logging.info("deleting iso %r", medium.name)
        progress = medium.deleteStorage()
        progress.waitForCompletion(-1)

    def mkdir(self, path):
        """Creates the specified directory path."""
        self.__check()
        logging.info("creating dir '%s'" % path)
        guestSession = self.__get_guest_session()
        guestSession.directoryCreate(path, 0, [])
        sleep(1)

    def mktempdir(self):
        """Creates a unique temp directory and returns the name."""
        self.__check()
        guestSession = self.__get_guest_session()
        path = guestSession.directoryCreateTemp('tmp_XXXXXXXX', 777, 'C:\\', False)
        logging.info("creating temp dir '%s'" % path)
        return path

    def copy_to_guest(self, src, dest):
        """Copys a file from the host to the guest machine.

        Keyword arguments:
        src -- path to the file on the host to be copied
        dest -- path for the new folder on the guest
        """
        self.__check()
        logging.info("copying '%s' to guest os at '%s'" % (src, dest))
        guestSession = self.__get_guest_session()
        # FIXME: Runs without error but doesn't copy
        progress = guestSession.fileCopyToGuest(src, dest, [0])
        progress.waitForCompletion(-1)
        # FIXME: fileExists raises VERR_NOT_FOUND (regardless of the file)
        if not progress.completed or not guestSession.fileExists(dest, False):
            # if not progress.completed:
            raise VBoxException("could not copy file")

    def copy_from_guest(self, src, dest):
        """Copys a file from the guest machine to the host.

        Keyword arguments:
        src -- path to the file on the guest to be copied
        dest -- path for the new file on the host
        """
        self.__check()
        logging.info("copying '%s' from guest os to '%s'" % (src, dest))
        guestSession = self.__get_guest_session()
        progress = guestSession.copyFrom(src, dest, None)
        progress.waitForCompletion(-1)
        if not os.path.exists(dest):
            raise VBoxException("could not copy %s from guest" % src)

    def copy_folder_to_guest(self, src, dest):
        """Copys a folder from the host to the guest machine.

        Keyword arguments:
        src -- path to the folder on the host to be copied
        dest -- path for the new folder on the guest
        """
        self.__check()
        logging.info("copying folder '%s' from guest os to '%s'" % (src, dest))
        for root, dirs, files in os.walk(src):
            path = self.join_path(dest, os.path.relpath(root, src))
            for dirname in dirs:
                self.mkdir(self.join_path(path, dirname))
            for filename in files:
                self.copy_to_guest(os.path.join(root, filename), self.join_path(path, filename))

    def copy_folder_from_guest(self, src, dest):
        """Copys a folder from the guest machine to the host.

        Keyword arguments:
        src -- path to the folder on the guest to be copied
        dest -- path for the new folder on the host
        """
        raise NotImplementedError()

    def remove_file(self, file_):
        """Removes a file from the guest machine.

        Keyword arguments:
        file -- path of the file to be removed
        """
        self.__check()
        logging.info("removing file '%s' from guest" % file_)
        guestSession = self.__get_guest_session()
        guestSession.fileRemove(file_)

    def execute(self, path, args=None, wait=False):
        """Executes a command on the guest machine.

        Keyword arguments:
        path -- command to be called (e.g. path to the executable)
        args -- list of arguments passed to the process (default [])
        wait -- wait until the process returns (default False)
        """
        if not args:
            args = list()
        self.__check()
        logging.info("executing %s %s" % (os.path.basename(path), ' '.join(args)))
        guestSession = self.__get_guest_session()
        flags = [self.mgr.constants.ProcessCreateFlag_WaitForProcessStartOnly] if not wait else [
            self.mgr.constants.ProcessCreateFlag_None]
        process = guestSession.processCreate(path, args, [], flags, 0)
        sleep(3)
        if wait:
            process.waitFor(self.mgr.constants.ProcessWaitForFlag_Terminate, 0)
        if not process.PID:
            raise VBoxException("could not execute '%s'" % path)
        return process
