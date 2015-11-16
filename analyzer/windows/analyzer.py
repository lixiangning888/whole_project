# Copyright (C) 2010-2015 Cuckoo Foundation, Accuvant, Inc. (bspengler@accuvant.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import socket
import struct
import random
import pkgutil
import logging
import hashlib
import xmlrpclib
import traceback
import subprocess
from ctypes import create_unicode_buffer, create_string_buffer, POINTER
from ctypes import c_wchar_p, byref, c_int, sizeof, cast, c_void_p, c_ulong
from threading import Lock, Thread
from datetime import datetime, timedelta

from lib.api.process import Process
from lib.common.abstracts import Package, Auxiliary
from lib.common.constants import PATHS, PIPE, SHUTDOWN_MUTEX, TERMINATE_EVENT
from lib.common.defines import KERNEL32, NTDLL
from lib.common.defines import ERROR_MORE_DATA, ERROR_PIPE_CONNECTED
from lib.common.defines import PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE
from lib.common.defines import PIPE_READMODE_MESSAGE, PIPE_WAIT
from lib.common.defines import PIPE_UNLIMITED_INSTANCES, INVALID_HANDLE_VALUE
from lib.common.defines import SYSTEM_PROCESS_INFORMATION
from lib.common.defines import EVENT_MODIFY_STATE
from lib.common.exceptions import CuckooError, CuckooPackageError
from lib.common.hashing import hash_file
from lib.common.results import upload_to_host
from lib.core.config import Config
from lib.core.packages import choose_package
from lib.core.privileges import grant_debug_privilege
from lib.core.startup import create_folders, init_logging
from modules import auxiliary

log = logging.getLogger()

BUFSIZE = 512
FILES_LIST = []
DUMPED_LIST = []
UPLOADPATH_LIST = []
PROCESS_LIST = []
PROTECTED_PATH_LIST = []
PROCESS_LOCK = Lock()
DEFAULT_DLL = None

SERVICES_PID = None
MONITORED_SERVICES = False
LASTINJECT_TIME = None

PID = os.getpid()
PPID = Process(pid=PID).get_parent_pid()
HIDE_PIDS = None

def in_protected_path(fname):
    """Checks file name against some protected names."""
    if not fname:
        return False

    fnamelower = fname.lower()

    for name in PROTECTED_PATH_LIST:
        if name[-1] == "\\" and fnamelower.startswith(name):
            return True
        elif fnamelower == name:
            return True

    return False

def add_protected_path(name):
    """Adds a pathname to the protected list"""
    if os.path.isdir(name) and name[-1] != "\\":
        PROTECTED_PATH_LIST.append(name.lower() + "\\")
    else:
        PROTECTED_PATH_LIST.append(name.lower())

def add_pid(pid):
    """Add a process to process list."""
    if isinstance(pid, (int, long, str)):
        log.info("Added new process to list with pid: %s", pid)
        PROCESS_LIST.append(int(pid))

def remove_pid(pid):
    """Remove a process to process list."""
    if isinstance(pid, (int, long, str)):
        log.info("Process with pid %s has terminated", pid)
        PROCESS_LIST.remove(pid)

def add_pids(pids):
    """Add PID."""
    if isinstance(pids, (tuple, list)):
        for pid in pids:
            add_pid(pid)
    else:
        add_pid(pids)

def add_file(file_path):
    """Add a file to file list."""
    if file_path not in FILES_LIST:
        log.info("Added new file to list with path: %s",
                 unicode(file_path).encode("utf-8", "replace"))
        FILES_LIST.append(file_path)

def dump_file(file_path):
    """Create a copy of the given file path."""
    duplicate = False
    try:
        if os.path.exists(file_path):
            sha256 = hash_file(hashlib.sha256, file_path)
            if sha256 in DUMPED_LIST:
                # The file was already dumped, just upload the alternate name for it.
                duplicate = True
        else:
            log.warning("File at path \"%s\" does not exist, skip.",
                        file_path.encode("utf-8", "replace"))
            return
    except IOError as e:
        log.warning("Unable to access file at path \"%s\": %s", file_path.encode("utf-8", "replace"), e)
        return

    if os.path.isdir(file_path):
        return
    name = os.path.basename(file_path)
    file_name = name[name.find(u":")+1:]
    if duplicate:
        idx = DUMPED_LIST.index(sha256)
        upload_path = UPLOADPATH_LIST[idx]
    else:
        upload_path = os.path.join("files",
                               str(random.randint(100000000, 9999999999)),
                               file_name.encode("utf-8", "replace"))
    try:
        upload_to_host(file_path, upload_path, duplicate)
        if not duplicate:
            DUMPED_LIST.append(sha256)
            UPLOADPATH_LIST.append(upload_path)
    except (IOError, socket.error) as e:
        log.error("Unable to upload dropped file at path \"%s\": %s",
                  file_path.encode("utf-8", "replace"), e)


def del_file(fname):
    dump_file(fname)

    # Filenames are case-insensitive in windows.
    fnames = [x.lower() for x in FILES_LIST]

    # If this filename exists in the FILES_LIST, then delete it, because it
    # doesn't exist anymore anyway.
    if fname.lower() in fnames:
        FILES_LIST.pop(fnames.index(fname.lower()))

def move_file(old_fname, new_fname):
    # Filenames are case-insensitive in windows.
    fnames = [x.lower() for x in FILES_LIST]
    lower_old_fname = old_fname.lower()
    # Check whether the old filename is in the FILES_LIST or if we moved a directory containing an existing dropped file
    for idx in range(len(fnames)):
        fname = fnames[idx]
        matchpath = None
        if fname == lower_old_fname:
            matchpath = lower_old_fname
            replacepath = new_fname
        elif lower_old_fname[-1] == u'\\' and fname.startswith(lower_old_fname):
           matchpath = lower_old_fname
           if new_fname[-1] == u'\\':
               replacepath = new_fname
           else:
               replacepath = new_fname + u"\\"
        elif fname.startswith(lower_old_fname + u"\\"):
           matchpath = lower_old_fname + u"\\"
           if new_fname[-1] == u'\\':
               replacepath = new_fname
           else:
               replacepath = new_fname + u"\\"

        if matchpath:
            # Replace the old filename by the new filename, or replace the subdirectory if moved
            FILES_LIST[idx] = fname.replace(matchpath, replacepath, 1)

def dump_files():
    """Dump all the dropped files."""
    for file_path in FILES_LIST:
        dump_file(file_path)

class PipeHandler(Thread):
    """Pipe Handler.

    This class handles the notifications received through the Pipe Server and
    decides what to do with them.
    """

    def __init__(self, h_pipe, options):
        """@param h_pipe: PIPE to read.
           @param options: options for analysis
        """
        Thread.__init__(self)
        self.h_pipe = h_pipe
        self.options = options

    def run(self):
        """Run handler.
        @return: operation status.
        """
        global MONITORED_SERVICES
        global LASTINJECT_TIME
        try:
            data = ""
            response = "OK"

            # Read the data submitted to the Pipe Server.
            while True:
                bytes_read = c_int(0)

                buf = create_string_buffer(BUFSIZE)
                success = KERNEL32.ReadFile(self.h_pipe,
                                            buf,
                                            sizeof(buf),
                                            byref(bytes_read),
                                            None)

                data += buf.value

                if not success and KERNEL32.GetLastError() == ERROR_MORE_DATA:
                    continue
                # elif not success or bytes_read.value == 0:
                #    if KERNEL32.GetLastError() == ERROR_BROKEN_PIPE:
                #        pass

                break

            if data:
                command = data.strip()

                # Debug, Regular, Warning, or Critical information from CuckooMon.
                if command.startswith("DEBUG:"):
                    log.debug(command[6:])
                elif command.startswith("INFO:"):
                    log.info(command[5:])
                elif command.startswith("WARNING:"):
                    log.warning(command[8:])
                elif command.startswith("CRITICAL:"):
                    log.critical(command[9:])

                # Parse the prefix for the received notification.
                # In case of GETPIDS we're gonna return the current process ID
                # and the process ID of our parent process (agent.py).
                elif command == "GETPIDS":
                    hidepids = set()
                    hidepids.update(HIDE_PIDS)
                    hidepids.update([PID, PPID])
                    response = struct.pack("%dI" % len(hidepids), *hidepids)

                # remove pid from process list because we received a notification
                # from kernel land
                elif command.startswith("KTERMINATE:"):
                    data = command[11:]
                    process_id = int(data)
                    if process_id:
                        if process_id in PROCESS_LIST:
                            remove_pid(process_id) 

                # same than below but we don't want to inject any DLLs because
                # it's a kernel analysis
                elif command.startswith("KPROCESS:"):
                    PROCESS_LOCK.acquire()
                    data = command[9:]
                    process_id = int(data)
                    thread_id = None
                    if process_id:
                        if process_id not in (PID, PPID):
                            if process_id not in PROCESS_LIST:
                                proc = Process(pid=process_id,thread_id=thread_id)
                                filepath = proc.get_filepath()
                                filename = os.path.basename(filepath)

                                if not in_protected_path(filename):
                                    add_pid(process_id)
                                    log.info("Announce process name : %s", filename)
                    PROCESS_LOCK.release()                
            
                elif command.startswith("KERROR:"):
                    error_msg = command[7:]
                    log.error("Error : %s", str(error_msg))
           
                # if a new driver has been loaded, we stop the analysis
                elif command == "KSUBVERT":
                    for pid in PROCESS_LIST:
                        log.info("Process with pid %s has terminated", pid)
                        PROCESS_LIST.remove(pid)

                # Handle case of a service being started by a monitored process
                # Switch the service type to own process behind its back so we
                # can monitor the service more easily with less noise
                elif command.startswith("SERVICE:"):
                    servname = command[8:]
                    si = subprocess.STARTUPINFO()
                    si.dwFlags = subprocess.STARTF_USESHOWWINDOW
                    si.wShowWindow = subprocess.SW_HIDE
                    subprocess.call("sc config " + servname + " type= own", startupinfo=si)
                    log.info("Announced starting service \"%s\"", servname)

                    if not MONITORED_SERVICES:
                        # Inject into services.exe so we can monitor service creation
                        # if tasklist previously failed to get the services.exe PID we'll be
                        # unable to inject
                        if SERVICES_PID:
                            servproc = Process(pid=SERVICES_PID,suspended=False)
                            filepath = servproc.get_filepath()
                            servproc.inject(dll=DEFAULT_DLL, interest=filepath, nosleepskip=True)
                            LASTINJECT_TIME = datetime.now()
                            servproc.close()
                            KERNEL32.Sleep(1000)
                            MONITORED_SERVICES = True
                        else:
                            log.error('Unable to monitor service %s' % (servname))

                # For now all we care about is bumping up our LASTINJECT_TIME to account for long delays between
                # injection and actual resume time where the DLL would have a chance to load in the new process
                # and report back to have its pid added to the list of monitored processes
                elif command.startswith("RESUME:"):
                    LASTINJECT_TIME = datetime.now()

                # Handle case of malware terminating a process -- notify the target
                # ahead of time so that it can flush its log buffer
                elif command.startswith("KILL:"):
                    PROCESS_LOCK.acquire()

                    process_id = int(command[5:])
                    if process_id not in (PID, PPID) and process_id in PROCESS_LIST:
                        # only notify processes we've hooked
                        event_name = TERMINATE_EVENT + str(process_id)
                        event_handle = KERNEL32.OpenEventA(EVENT_MODIFY_STATE, False, event_name)
                        if not event_handle:
                            log.warning("Unable to open termination event for pid %u.", process_id)
                        else:
                            log.info("Notified of termination of process with pid %u.", process_id)
                            # dump the memory of exiting processes
                            if self.options.get("procmemdump"):
                                p = Process(pid=process_id)
                                p.dump_memory()
                            # make sure process is aware of the termination
                            KERNEL32.SetEvent(event_handle)
                            KERNEL32.CloseHandle(event_handle)

                    PROCESS_LOCK.release()
                # Handle notification of cuckoomon loading in a process
                elif command.startswith("LOADED:"):
                    PROCESS_LOCK.acquire()
                    process_id = int(command[7:])
                    if process_id not in PROCESS_LIST:
                        add_pids(process_id)
                    PROCESS_LOCK.release()
                    log.info("Cuckoomon successfully loaded in process with pid %u.", process_id)

                # In case of PID, the client is trying to notify the creation of
                # a new process to be injected and monitored.
                elif command.startswith("PROCESS:"):
                    # We acquire the process lock in order to prevent the analyzer
                    # to terminate the analysis while we are operating on the new
                    # process.
                    PROCESS_LOCK.acquire()

                    # Set the current DLL to the default one provided
                    # at submission.
                    dll = DEFAULT_DLL
                    suspended = False
                    # We parse the process ID.
                    data = command[8:]
                    if len(data) > 2 and data[1] == ':':
                        if data[0] == '1':
                            suspended = True
                        data = command[10:]

                    process_id = thread_id = None
                    if "," not in data:
                        if data.isdigit():
                            process_id = int(data)
                    elif data.count(",") == 1:
                        process_id, param = data.split(",")
                        thread_id = None
                        if process_id.isdigit():
                            process_id = int(process_id)
                        else:
                            process_id = None

                        if param.isdigit():
                            thread_id = int(param)

                    if process_id:
                        if process_id not in (PID, PPID):
                            # We inject the process only if it's not being
                            # monitored already, otherwise we would generate
                            # polluted logs.
                            if process_id not in PROCESS_LIST:
                                # Open the process and inject the DLL.
                                # Hope it enjoys it.
                                proc = Process(pid=process_id,
                                               thread_id=thread_id,
                                               suspended=suspended)

                                filepath = proc.get_filepath()
                                is_64bit = proc.is_64bit()
                                filename = os.path.basename(filepath)

                                log.info("Announced %s process name: %s pid: %d", "64-bit" if is_64bit else "32-bit", filename, process_id)

                                if not in_protected_path(filename):
                                    res = proc.inject(dll, filepath)
                                    LASTINJECT_TIME = datetime.now()
                                proc.close()
                        else:
                            log.warning("Received request to inject Cuckoo "
                                        "process with pid %d, skip", process_id)

                    # Once we're done operating on the processes list, we release
                    # the lock.
                    PROCESS_LOCK.release()
                # In case of FILE_NEW, the client is trying to notify the creation
                # of a new file.
                elif command.startswith("FILE_NEW:"):
                    # We extract the file path.
                    file_path = unicode(command[9:].decode("utf-8"))
                    # We add the file to the list.
                    add_file(file_path)
                # In case of FILE_DEL, the client is trying to notify an ongoing
                # deletion of an existing file, therefore we need to dump it
                # straight away.
                elif command.startswith("FILE_DEL:"):
                    # Extract the file path.
                    file_path = unicode(command[9:].decode("utf-8"))
                    # Dump the file straight away.
                    del_file(file_path)
                elif command.startswith("FILE_MOVE:"):
                    # Syntax = "FILE_MOVE:old_file_path::new_file_path".
                    if "::" in command[10:]:
                        old_fname, new_fname = command[10:].split("::", 1)
                        move_file(unicode(old_fname.decode("utf-8")),
                                  unicode(new_fname.decode("utf-8")))
                else:
                    log.warning("Received unknown command from cuckoomon: %s", command)

            KERNEL32.WriteFile(self.h_pipe,
                               create_string_buffer(response),
                               len(response),
                               byref(bytes_read),
                               None)

            KERNEL32.CloseHandle(self.h_pipe)

            return True
        except Exception as e:
            error_exc = traceback.format_exc()
            log.exception(error_exc)
            return True

class PipeServer(Thread):
    """Cuckoo PIPE server.

    This Pipe Server receives notifications from the injected processes for
    new processes being spawned and for files being created or deleted.
    """

    def __init__(self, options, pipe_name=PIPE):
        """@param pipe_name: Cuckoo PIPE server name."""
        Thread.__init__(self)
        self.pipe_name = pipe_name
        self.options = options
        self.do_run = True

    def stop(self):
        """Stop PIPE server."""
        self.do_run = False

    def run(self):
        """Create and run PIPE server.
        @return: operation status.
        """
        try:
            while self.do_run:
                # Create the Named Pipe.
                h_pipe = KERNEL32.CreateNamedPipeA(self.pipe_name,
                                                   PIPE_ACCESS_DUPLEX,
                                                   PIPE_TYPE_MESSAGE |
                                                   PIPE_READMODE_MESSAGE |
                                                   PIPE_WAIT,
                                                   PIPE_UNLIMITED_INSTANCES,
                                                   BUFSIZE,
                                                   BUFSIZE,
                                                   0,
                                                   None)

                if h_pipe == INVALID_HANDLE_VALUE:
                    return False

                # If we receive a connection to the pipe, we invoke the handler.
                if KERNEL32.ConnectNamedPipe(h_pipe, None) or KERNEL32.GetLastError() == ERROR_PIPE_CONNECTED:
                    handler = PipeHandler(h_pipe, self.options)
                    handler.daemon = True
                    handler.start()
                else:
                    KERNEL32.CloseHandle(h_pipe)

            return True
        except Exception as e:
            error_exc = traceback.format_exc()
            log.exception(error_exc)
            return True

class Analyzer:
    """Cuckoo Windows Analyzer.

    This class handles the initialization and execution of the analysis
    procedure, including handling of the pipe server, the auxiliary modules and
    the analysis packages.
    """
    PIPE_SERVER_COUNT = 4

    def __init__(self):
        self.pipes = [None]*self.PIPE_SERVER_COUNT
        self.config = None
        self.target = None

    def pids_from_process_name_list(self, namelist):
        proclist = []
        pidlist = []
        buf = create_string_buffer(1024 * 1024)
        p = cast(buf, c_void_p)
        retlen = c_ulong(0)
        retval = NTDLL.NtQuerySystemInformation(5, buf, 1024 * 1024, byref(retlen))
        if retval:
           return []
        proc = cast(p, POINTER(SYSTEM_PROCESS_INFORMATION)).contents
        while proc.NextEntryOffset:
            p.value += proc.NextEntryOffset
            proc = cast(p, POINTER(SYSTEM_PROCESS_INFORMATION)).contents
            proclist.append((proc.ImageName.Buffer[:proc.ImageName.Length/2], proc.UniqueProcessId))

        for proc in proclist:
            lowerproc = proc[0].lower()
            for name in namelist:
                if lowerproc == name:
                    pidlist.append(proc[1])
                    break
        return pidlist

    def prepare(self):
        """Prepare env for analysis."""
        global DEFAULT_DLL
        global SERVICES_PID
        global HIDE_PIDS

        # Get SeDebugPrivilege for the Python process. It will be needed in
        # order to perform the injections.
        grant_debug_privilege()

        # Create the folders used for storing the results.
        create_folders()

        add_protected_path(os.getcwd())
        add_protected_path(PATHS["root"])

        # Initialize logging.
        init_logging()

        # Parse the analysis configuration file generated by the agent.
        self.config = Config(cfg="analysis.conf")

        # Set virtual machine clock.
        clock = datetime.strptime(self.config.clock, "%Y%m%dT%H:%M:%S")
        # Setting date and time.
        # NOTE: Windows system has only localized commands with date format
        # following localization settings, so these commands for english date
        # format cannot work in other localizations.
        # In addition DATE and TIME commands are blocking if an incorrect
        # syntax is provided, so an echo trick is used to bypass the input
        # request and not block analysis.
        thedate = clock.strftime("%m-%d-%y")
        thetime = clock.strftime("%H:%M:%S")
        os.system("echo:|date {0}".format(thedate))
        os.system("echo:|time {0}".format(thetime))
        log.info("Date set to: {0}, time set to: {1}".format(thedate, thetime))

        # Set the default DLL to be used by the PipeHandler.
        DEFAULT_DLL = self.config.get_options().get("dll")

        # get PID for services.exe for monitoring services
        svcpid = self.pids_from_process_name_list(["services.exe"])
        if svcpid:
            SERVICES_PID = svcpid[0]

        protected_procname_list = [
            "vmwareuser.exe",
            "vmwareservice.exe",
            "vboxservice.exe",
            "vboxtray.exe",
            "sandboxiedcomlaunch.exe",
            "sandboxierpcss.exe",
            "procmon.exe",
            "regmon.exe",
            "filemon.exe",
            "wireshark.exe",
            "netmon.exe",
            "prl_tools_service.exe",
            "prl_tools.exe",
            "prl_cc.exe",
            "sharedintapp.exe",
            "vmtoolsd.exe",
            "vmsrvc.exe",
            "python.exe",
            "perl.exe",
        ]

        HIDE_PIDS = set(self.pids_from_process_name_list(protected_procname_list))

        # Initialize and start the Pipe Servers. This is going to be used for
        # communicating with the injected and monitored processes.
        for x in xrange(self.PIPE_SERVER_COUNT):
            self.pipes[x] = PipeServer(self.config.get_options())
            self.pipes[x].daemon = True
            self.pipes[x].start()

        # We update the target according to its category. If it's a file, then
        # we store the path.
        if self.config.category == "file":
            self.target = os.path.join(os.environ["TEMP"] + os.sep,
                                       str(self.config.file_name))
        # If it's a URL, well.. we store the URL.
        else:
            self.target = self.config.target

    def complete(self):
        """End analysis."""
        # Stop the Pipe Servers.
        for x in xrange(self.PIPE_SERVER_COUNT):
            self.pipes[x].stop()

        # Dump all the notified files.
        dump_files()

        # Hell yeah.
        log.info("Analysis completed.")

    def run(self):
        """Run analysis.
        @return: operation status.
        """
        self.prepare()

        log.debug("Starting analyzer from: %s", os.getcwd())
        log.debug("Storing results at: %s", PATHS["root"])
        log.debug("Pipe server name: %s", PIPE)

        # If no analysis package was specified at submission, we try to select
        # one automatically.
        if not self.config.package:
            log.debug("No analysis package specified, trying to detect "
                      "it automagically.")

            # If the analysis target is a file, we choose the package according
            # to the file format.
            if self.config.category == "file":
                package = choose_package(self.config.file_type, self.config.file_name, self.config.exports)
            # If it's an URL, we'll just use the default Internet Explorer
            # package.
            else:
                package = "ie"

            # If we weren't able to automatically determine the proper package,
            # we need to abort the analysis.
            if not package:
                raise CuckooError("No valid package available for file "
                                  "type: {0}".format(self.config.file_type))

            log.info("Automatically selected analysis package \"%s\"", package)
        # Otherwise just select the specified package.
        else:
            package = self.config.package

        # Generate the package path.
        package_name = "modules.packages.%s" % package

        # Try to import the analysis package.
        try:
            __import__(package_name, globals(), locals(), ["dummy"], -1)
        # If it fails, we need to abort the analysis.
        except ImportError:
            raise CuckooError("Unable to import package \"{0}\", does "
                              "not exist.".format(package_name))

        # Initialize the package parent abstract.
        Package()

        # Enumerate the abstract subclasses.
        try:
            package_class = Package.__subclasses__()[0]
        except IndexError as e:
            raise CuckooError("Unable to select package class "
                              "(package={0}): {1}".format(package_name, e))

        # Initialize the analysis package.
        pack = package_class(self.config.get_options(), self.config)

        # Initialize Auxiliary modules
        Auxiliary()
        prefix = auxiliary.__name__ + "."
        for loader, name, ispkg in pkgutil.iter_modules(auxiliary.__path__, prefix):
            if ispkg:
                continue

            # Import the auxiliary module.
            try:
                __import__(name, globals(), locals(), ["dummy"], -1)
            except ImportError as e:
                log.warning("Unable to import the auxiliary module "
                            "\"%s\": %s", name, e)

        # Walk through the available auxiliary modules.
        aux_enabled, aux_avail = [], []
        for module in Auxiliary.__subclasses__():
            # Try to start the auxiliary module.
            try:
                aux = module(self.config.get_options(), self.config)
                aux_avail.append(aux)
                aux.start()
            except (NotImplementedError, AttributeError):
                log.warning("Auxiliary module %s was not implemented",
                            module.__name__)
            except Exception as e:
                log.warning("Cannot execute auxiliary module %s: %s",
                            module.__name__, e)
            else:
                log.debug("Started auxiliary module %s", module.__name__)
                aux_enabled.append(aux)

        # Start analysis package. If for any reason, the execution of the
        # analysis package fails, we have to abort the analysis.
        try:
            pids = pack.start(self.target)
        except NotImplementedError:
            raise CuckooError("The package \"{0}\" doesn't contain a run "
                              "function.".format(package_name))
        except CuckooPackageError as e:
            raise CuckooError("The package \"{0}\" start function raised an "
                              "error: {1}".format(package_name, e))
        except Exception as e:
            raise CuckooError("The package \"{0}\" start function encountered "
                              "an unhandled exception: "
                              "{1}".format(package_name, e))

        # If the analysis package returned a list of process IDs, we add them
        # to the list of monitored processes and enable the process monitor.
        if pids:
            add_pids(pids)
            pid_check = True

        # If the package didn't return any process ID (for example in the case
        # where the package isn't enabling any behavioral analysis), we don't
        # enable the process monitor.
        else:
            log.info("No process IDs returned by the package, running "
                     "for the full timeout.")
            pid_check = False

        # Check in the options if the user toggled the timeout enforce. If so,
        # we need to override pid_check and disable process monitor.
        if self.config.enforce_timeout:
            log.info("Enabled timeout enforce, running for the full timeout.")
            pid_check = False

        time_counter = 0
        kernel_analysis = self.config.get_options().get("kernel_analysis", False)

        if kernel_analysis != False:
            kernel_analysis = True

        emptytime = None

        while True:
            time_counter += 1
            if time_counter == int(self.config.timeout):
                log.info("Analysis timeout hit, terminating analysis.")
                break

            # If the process lock is locked, it means that something is
            # operating on the list of monitored processes. Therefore we
            # cannot proceed with the checks until the lock is released.
            if PROCESS_LOCK.locked():
                KERNEL32.Sleep(1000)
                continue

            try:
                # If the process monitor is enabled we start checking whether
                # the monitored processes are still alive.
                if pid_check:
                    if not kernel_analysis:
                        for pid in PROCESS_LIST:
                            if not Process(pid=pid).is_alive():
                                log.info("Process with pid %s has terminated", pid)
                                PROCESS_LIST.remove(pid)

                        # If none of the monitored processes are still alive, we
                        # can terminate the analysis.
                        if not PROCESS_LIST and (not LASTINJECT_TIME or (datetime.now() >= (LASTINJECT_TIME + timedelta(seconds=15)))):
                            if emptytime and (datetime.now() >= (emptytime + timedelta(seconds=5))):
                                log.info("Process list is empty, "
                                        "terminating analysis.")
                                break
                            elif not emptytime:
                                emptytime = datetime.now()
                        else:
                            emptytime = None

                    # Update the list of monitored processes available to the
                    # analysis package. It could be used for internal
                    # operations within the module.
                    pack.set_pids(PROCESS_LIST)

                try:
                    # The analysis packages are provided with a function that
                    # is executed at every loop's iteration. If such function
                    # returns False, it means that it requested the analysis
                    # to be terminate.
                    if not pack.check():
                        log.info("The analysis package requested the "
                                 "termination of the analysis.")
                        break

                # If the check() function of the package raised some exception
                # we don't care, we can still proceed with the analysis but we
                # throw a warning.
                except Exception as e:
                    log.warning("The package \"%s\" check function raised "
                                "an exception: %s", package_name, e)
            finally:
                # Zzz.
                KERNEL32.Sleep(1000)

        # Create the shutdown mutex.
        KERNEL32.CreateMutexA(None, False, SHUTDOWN_MUTEX)

        # since the various processes poll for the existence of the mutex, sleep
        # for a second to ensure they see it before they're terminated
        KERNEL32.Sleep(1000)

        try:
            # Before shutting down the analysis, the package can perform some
            # final operations through the finish() function.
            pack.finish()
        except Exception as e:
            log.warning("The package \"%s\" finish function raised an "
                        "exception: %s", package_name, e)

        # Terminate the Auxiliary modules.
        for aux in aux_enabled:
            try:
                aux.stop()
            except (NotImplementedError, AttributeError):
                continue
            except Exception as e:
                log.warning("Cannot terminate auxiliary module %s: %s",
                            aux.__class__.__name__, e)

        # Tell all processes to flush their logs regardless of terminate_processes setting
        if not kernel_analysis:
            for pid in PROCESS_LIST:
                proc = Process(pid=pid)
                if proc.is_alive():
                    try:
                        proc.set_terminate_event()
                    except:
                        continue

        if self.config.terminate_processes:
            # Try to terminate remaining active processes. We do this to make sure
            # that we clean up remaining open handles (sockets, files, etc.).
            log.info("Terminating remaining processes before shutdown.")

            if not kernel_analysis:
                for pid in PROCESS_LIST:
                    proc = Process(pid=pid)
                    if proc.is_alive():
                        try:
                            if not proc.is_critical():
                                proc.terminate()
                            else:
                                log.info("Not terminating critical process with pid %d.", proc.pid)
                        except:
                            continue

        # Run the finish callback of every available Auxiliary module.
        for aux in aux_avail:
            try:
                aux.finish()
            except (NotImplementedError, AttributeError):
                continue
            except Exception as e:
                log.warning("Exception running finish callback of auxiliary "
                            "module %s: %s", aux.__class__.__name__, e)

        # Let's invoke the completion procedure.
        self.complete()

        return True

if __name__ == "__main__":
    success = False
    error = ""

    try:
        # Initialize the main analyzer class.
        analyzer = Analyzer()

        # Run it and wait for the response.
        success = analyzer.run()

    # This is not likely to happen.
    except KeyboardInterrupt:
        error = "Keyboard Interrupt"

    # If the analysis process encountered a critical error, it will raise a
    # CuckooError exception, which will force the termination of the analysis.
    # Notify the agent of the failure. Also catch unexpected exceptions.
    except Exception as e:
        # Store the error.
        error_exc = traceback.format_exc()
        error = str(e)

        # Just to be paranoid.
        if len(log.handlers):
            log.exception(error_exc)
        else:
            sys.stderr.write("{0}\n".format(error_exc))

    # Once the analysis is completed or terminated for any reason, we report
    # back to the agent, notifying that it can report back to the host.
    finally:
        # Establish connection with the agent XMLRPC server.
        server = xmlrpclib.Server("http://127.0.0.1:8000")
        server.complete(success, error, PATHS["root"])
