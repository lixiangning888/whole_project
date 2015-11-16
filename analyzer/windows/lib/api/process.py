# Copyright (C) 2010-2015 Cuckoo Foundation, Accuvant, Inc. (bspengler@accuvant.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
import random
import subprocess
import platform
import urllib
import base64
from time import time
from ctypes import byref, c_ulong, create_string_buffer, c_int, sizeof
from shutil import copy

from lib.common.constants import PIPE, PATHS, SHUTDOWN_MUTEX, TERMINATE_EVENT
from lib.common.defines import ULONG_PTR
from lib.common.defines import KERNEL32, NTDLL, SYSTEM_INFO, STILL_ACTIVE
from lib.common.defines import THREAD_ALL_ACCESS, PROCESS_ALL_ACCESS, TH32CS_SNAPPROCESS
from lib.common.defines import STARTUPINFO, PROCESS_INFORMATION, PROCESSENTRY32
from lib.common.defines import CREATE_NEW_CONSOLE, CREATE_SUSPENDED
from lib.common.defines import MEM_RESERVE, MEM_COMMIT, PAGE_READWRITE
from lib.common.defines import MEMORY_BASIC_INFORMATION
from lib.common.defines import WAIT_TIMEOUT, EVENT_MODIFY_STATE
from lib.common.defines import MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE
from lib.common.defines import GENERIC_READ, GENERIC_WRITE, OPEN_EXISTING
from lib.common.errors import get_error_string
from lib.common.rand import random_string
from lib.common.results import NetlogFile
from lib.core.config import Config
from lib.core.log import LogServer

IOCTL_PID = 0x222008
IOCTL_CUCKOO_PATH = 0x22200C
PATH_KERNEL_DRIVER = "\\\\.\\DriverSSDT"

log = logging.getLogger(__name__)

def is_os_64bit():
    return platform.machine().endswith('64')

def randomize_bin(bin_path, ext):
    """Randomize binary name.
    @return: new binary path.
    """
    new_bin_name = random_string(6)
    new_bin_path = os.path.join(os.getcwd(), ext, "{0}.{1}".format(new_bin_name, ext))

    try:
        copy(bin_path, new_bin_path)
        return new_bin_path
    except:
        return bin_path

def get_referrer_url(interest):
    """Get a Google referrer URL
    @return: URL to be added to the analysis config
    """

    if "://" not in interest:
        return ""

    escapedurl = urllib.quote(interest, '')
    itemidx = str(random.randint(1, 30))
    vedstr = "0CCEQfj" + base64.urlsafe_b64encode(random_string(random.randint(5, 8) * 3))
    eistr = base64.urlsafe_b64encode(random_string(12))
    usgstr = "AFQj" + base64.urlsafe_b64encode(random_string(12))
    referrer = "http://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd={0}&ved={1}&url={2}&ei={3}&usg={4}".format(itemidx, vedstr, escapedurl, eistr, usgstr)
    return referrer

class Process:
    """Windows process."""
    first_process = True
    # This adds 1 up to 30 times of 20 minutes to the startup
    # time of the process, therefore bypassing anti-vm checks
    # which check whether the VM has only been up for <10 minutes.
    startup_time = random.randint(1, 30) * 20 * 60 * 1000

    def __init__(self, pid=0, h_process=0, thread_id=0, h_thread=0, suspended=False):
        """@param pid: PID.
        @param h_process: process handle.
        @param thread_id: thread id.
        @param h_thread: thread handle.
        """
        self.pid = pid
        self.h_process = h_process
        self.thread_id = thread_id
        self.h_thread = h_thread
        self.suspended = suspended
        self.system_info = SYSTEM_INFO()
        self.logserver_path = "\\\\.\\PIPE\\" + random_string(8, 12)
        self.logserver = None

    def __del__(self):
        """Close open handles."""
        if self.h_process and self.h_process != KERNEL32.GetCurrentProcess():
            KERNEL32.CloseHandle(self.h_process)
        if self.h_thread:
            KERNEL32.CloseHandle(self.h_thread)

    def get_system_info(self):
        """Get system information."""
        KERNEL32.GetSystemInfo(byref(self.system_info))

    def open(self):
        """Open a process and/or thread.
        @return: operation status.
        """
        ret = bool(self.pid or self.thread_id)
        if self.pid and not self.h_process:
            if self.pid == os.getpid():
                self.h_process = KERNEL32.GetCurrentProcess()
            else:
                self.h_process = KERNEL32.OpenProcess(PROCESS_ALL_ACCESS,
                                                      False,
                                                      self.pid)
            ret = True

        if self.thread_id and not self.h_thread:
            self.h_thread = KERNEL32.OpenThread(THREAD_ALL_ACCESS,
                                                False,
                                                self.thread_id)
            ret = True
        return ret

    def close(self):
        """Close any open handles.
        @return: operation status.
        """
        ret = bool(self.h_process or self.h_thread)
        NT_SUCCESS = lambda val: val >= 0

        if self.h_process:
            ret = NT_SUCCESS(KERNEL32.CloseHandle(self.h_process))
            self.h_process = None

        if self.h_thread:
            ret = NT_SUCCESS(KERNEL32.CloseHandle(self.h_thread))
            self.h_thread = None

        return ret

    def exit_code(self):
        """Get process exit code.
        @return: exit code value.
        """
        if not self.h_process:
            self.open()

        exit_code = c_ulong(0)
        KERNEL32.GetExitCodeProcess(self.h_process, byref(exit_code))

        return exit_code.value

    def get_filepath(self):
        """Get process image file path.
        @return: decoded file path.
        """
        if not self.h_process:
            self.open()

        NT_SUCCESS = lambda val: val >= 0

        pbi = create_string_buffer(200)
        size = c_int()

        # Set return value to signed 32bit integer.
        NTDLL.NtQueryInformationProcess.restype = c_int

        ret = NTDLL.NtQueryInformationProcess(self.h_process,
                                              27,
                                              byref(pbi),
                                              sizeof(pbi),
                                              byref(size))

        if NT_SUCCESS(ret) and size.value > 8:
            try:
                fbuf = pbi.raw[8:]
                fbuf = fbuf[:fbuf.find('\0\0')+1]
                return fbuf.decode('utf16', errors="ignore")
            except:
                return ""

        return ""

    def is_alive(self):
        """Process is alive?
        @return: process status.
        """
        return self.exit_code() == STILL_ACTIVE

    def is_critical(self):
        """Determines if process is 'critical' or not, so we can prevent
           terminating it
        """
        if not self.h_process:
            self.open()

        NT_SUCCESS = lambda val: val >= 0

        val = c_ulong(0)
        retlen = c_ulong(0)
        ret = NTDLL.NtQueryInformationProcess(self.h_process, 29, byref(val), sizeof(val), byref(retlen))
        if NT_SUCCESS(ret) and val.value:
            return True
        return False

    def get_parent_pid(self):
        """Get the Parent Process ID."""
        if not self.h_process:
            self.open()

        NT_SUCCESS = lambda val: val >= 0

        pbi = (ULONG_PTR * 6)()
        size = c_ulong()

        # Set return value to signed 32bit integer.
        NTDLL.NtQueryInformationProcess.restype = c_int

        ret = NTDLL.NtQueryInformationProcess(self.h_process,
                                              0,
                                              byref(pbi),
                                              sizeof(pbi),
                                              byref(size))

        if NT_SUCCESS(ret) and size.value == sizeof(pbi):
            return pbi[5]

        return None

    def kernel_analyze(self):
        """zer0m0n kernel analysis
        """
        log.info("Starting kernel analysis")
        log.info("Installing driver")
        if is_os_64bit(): 
            sys_file = os.path.join(os.getcwd(), "dll", "zer0m0n_x64.sys")
        else:
            sys_file = os.path.join(os.getcwd(), "dll", "zer0m0n.sys")
        exe_file = os.path.join(os.getcwd(), "dll", "logs_dispatcher.exe")
        if not sys_file or not exe_file or not os.path.exists(sys_file) or not os.path.exists(exe_file):
                log.warning("No valid zer0m0n files to be used for process with pid %d, injection aborted", self.pid)
                return False
                
        exe_name = random_string(6)
        service_name = random_string(6)
        driver_name = random_string(6)
        inf_data = '[Version]\r\nSignature = "$Windows NT$"\r\nClass = "ActivityMonitor"\r\nClassGuid = {b86dff51-a31e-4bac-b3cf-e8cfe75c9fc2}\r\nProvider= %Prov%\r\nDriverVer = 22/01/2014,1.0.0.0\r\nCatalogFile = %DriverName%.cat\r\n[DestinationDirs]\r\nDefaultDestDir = 12\r\nMiniFilter.DriverFiles = 12\r\n[DefaultInstall]\r\nOptionDesc = %ServiceDescription%\r\nCopyFiles = MiniFilter.DriverFiles\r\n[DefaultInstall.Services]\r\nAddService = %ServiceName%,,MiniFilter.Service\r\n[DefaultUninstall]\r\nDelFiles = MiniFilter.DriverFiles\r\n[DefaultUninstall.Services]\r\nDelService = %ServiceName%,0x200\r\n[MiniFilter.Service]\r\nDisplayName= %ServiceName%\r\nDescription= %ServiceDescription%\r\nServiceBinary= %12%\\%DriverName%.sys\r\nDependencies = "FltMgr"\r\nServiceType = 2\r\nStartType = 3\r\nErrorControl = 1\r\nLoadOrderGroup = "FSFilter Activity Monitor"\r\nAddReg = MiniFilter.AddRegistry\r\n[MiniFilter.AddRegistry]\r\nHKR,,"DebugFlags",0x00010001 ,0x0\r\nHKR,"Instances","DefaultInstance",0x00000000,%DefaultInstance%\r\nHKR,"Instances\\"%Instance1.Name%,"Altitude",0x00000000,%Instance1.Altitude%\r\nHKR,"Instances\\"%Instance1.Name%,"Flags",0x00010001,%Instance1.Flags%\r\n[MiniFilter.DriverFiles]\r\n%DriverName%.sys\r\n[SourceDisksFiles]\r\n'+driver_name+'.sys = 1,,\r\n[SourceDisksNames]\r\n1 = %DiskId1%,,,\r\n[Strings]\r\n'+'Prov = "'+random_string(8)+'"\r\nServiceDescription = "'+random_string(12)+'"\r\nServiceName = "'+service_name+'"\r\nDriverName = "'+driver_name+'"\r\nDiskId1 = "'+service_name+' Device Installation Disk"\r\nDefaultInstance = "'+service_name+' Instance"\r\nInstance1.Name = "'+service_name+' Instance"\r\nInstance1.Altitude = "370050"\r\nInstance1.Flags = 0x0'
                
        new_inf = os.path.join(os.getcwd(), "dll", "{0}.inf".format(service_name))
        new_sys = os.path.join(os.getcwd(), "dll", "{0}.sys".format(driver_name))
        copy(sys_file, new_sys)
        new_exe = os.path.join(os.getcwd(), "dll", "{0}.exe".format(exe_name))
        copy(exe_file, new_exe)
        log.info("[-] Driver name : "+new_sys)
        log.info("[-] Inf name : "+new_inf)
        log.info("[-] Application name : "+new_exe)
        log.info("[-] Service : "+service_name)
                
        fh = open(new_inf,"w")
        fh.write(inf_data)
        fh.close()
        
        os_is_64bit = is_os_64bit()
        if os_is_64bit:
            wow64 = c_ulong(0)
            KERNEL32.Wow64DisableWow64FsRedirection(byref(wow64))
                
        os.system('cmd /c "rundll32 setupapi.dll, InstallHinfSection DefaultInstall 132 '+new_inf+'"')
        os.system("net start "+service_name)
                
        si = STARTUPINFO()
        si.cb = sizeof(si)
        pi = PROCESS_INFORMATION()
        cr = CREATE_NEW_CONSOLE 
                
        ldp = KERNEL32.CreateProcessA(new_exe, None, None, None, None, cr, None, os.getenv("TEMP"), byref(si), byref(pi))
        if not ldp:
            if os_is_64bit:
                KERNEL32.Wow64RevertWow64FsRedirection(wow64)
            log.error("Failed starting "+exe_name+".exe.")
            return False
        
        config_path = os.path.join(os.getenv("TEMP"), "%s.ini" % self.pid)
        with open(config_path, "w") as config:
            cfg = Config("analysis.conf")

            config.write("host-ip={0}\n".format(cfg.ip))
            config.write("host-port={0}\n".format(cfg.port))
            config.write("pipe={0}\n".format(PIPE))
                
        log.info("Sending startup information")
        hFile = KERNEL32.CreateFileA(PATH_KERNEL_DRIVER, GENERIC_READ|GENERIC_WRITE,
                                    0, None, OPEN_EXISTING, 0, None)
        if os_is_64bit:
            KERNEL32.Wow64RevertWow64FsRedirection(wow64)
        if hFile:
            p = Process(pid=os.getpid())
            ppid = p.get_parent_pid()
            pid_vboxservice = 0
            pid_vboxtray = 0

            # get pid of VBoxService.exe and VBoxTray.exe
            proc_info = PROCESSENTRY32()
            proc_info.dwSize = sizeof(PROCESSENTRY32)

            snapshot = KERNEL32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            flag = KERNEL32.Process32First(snapshot, byref(proc_info))
            while flag:
                if proc_info.sz_exeFile == "VBoxService.exe":
                    log.info("VBoxService.exe found !")
                    pid_vboxservice = proc_info.th32ProcessID
                    flag = 0 
                elif proc_info.sz_exeFile == "VBoxTray.exe":
                    pid_vboxtray = proc_info.th32ProcessID
                    log.info("VBoxTray.exe found !")
                    flag = 0
                flag = KERNEL32.Process32Next(snapshot, byref(proc_info)) 
            bytes_returned = c_ulong(0)
            msg = str(self.pid)+"_"+str(ppid)+"_"+str(os.getpid())+"_"+str(pi.dwProcessId)+"_"+str(pid_vboxservice)+"_"+str(pid_vboxtray)+'\0'
            KERNEL32.DeviceIoControl(hFile, IOCTL_PID, msg, len(msg), None, 0, byref(bytes_returned), None)
            msg = os.getcwd()+'\0'
            KERNEL32.DeviceIoControl(hFile, IOCTL_CUCKOO_PATH, unicode(msg), len(unicode(msg)), None, 0, byref(bytes_returned), None)
        else:
            log.warning("Failed to access kernel driver")

        return True

    def execute(self, path, args=None, suspended=False, kernel_analysis=False):
        """Execute sample process.
        @param path: sample path.
        @param args: process args.
        @param suspended: is suspended.
        @return: operation status.
        """
        if not os.access(path, os.X_OK):
            log.error("Unable to access file at path \"%s\", "
                      "execution aborted", path)
            return False

        startup_info = STARTUPINFO()
        startup_info.cb = sizeof(startup_info)
        # STARTF_USESHOWWINDOW
        startup_info.dwFlags = 1
        # SW_SHOWNORMAL
        startup_info.wShowWindow = 1
        process_info = PROCESS_INFORMATION()

        arguments = "\"" + path + "\" "
        if args:
            arguments += args

        creation_flags = CREATE_NEW_CONSOLE
        if suspended:
            self.suspended = True
            creation_flags += CREATE_SUSPENDED

        created = KERNEL32.CreateProcessA(path,
                                          arguments,
                                          None,
                                          None,
                                          None,
                                          creation_flags,
                                          None,
                                          os.getenv("TEMP"),
                                          byref(startup_info),
                                          byref(process_info))

        if created:
            self.pid = process_info.dwProcessId
            self.h_process = process_info.hProcess
            self.thread_id = process_info.dwThreadId
            self.h_thread = process_info.hThread
            log.info("Successfully executed process from path \"%s\" with "
                     "arguments \"%s\" with pid %d", path, args or "", self.pid)
            if kernel_analysis:
                return self.kernel_analyze()
            return True
        else:
            log.error("Failed to execute process from path \"%s\" with "
                      "arguments \"%s\" (Error: %s)", path, args,
                      get_error_string(KERNEL32.GetLastError()))
            return False

    def resume(self):
        """Resume a suspended thread.
        @return: operation status.
        """
        if not self.suspended:
            log.warning("The process with pid %d was not suspended at creation"
                        % self.pid)
            return False

        if not self.h_thread:
            return False

        KERNEL32.Sleep(2000)

        if KERNEL32.ResumeThread(self.h_thread) != -1:
            self.suspended = False
            log.info("Successfully resumed process with pid %d", self.pid)
            return True
        else:
            log.error("Failed to resume process with pid %d", self.pid)
            return False

    def set_terminate_event(self):
        """Sets the termination event for the process.
        """
        if self.h_process == 0:
            self.open()

        event_name = TERMINATE_EVENT + str(self.pid)
        event_handle = KERNEL32.OpenEventA(EVENT_MODIFY_STATE, False, event_name)
        if event_handle:
            # make sure process is aware of the termination
            KERNEL32.SetEvent(event_handle)
            KERNEL32.CloseHandle(event_handle)
            KERNEL32.Sleep(500)

    def terminate(self):
        """Terminate process.
        @return: operation status.
        """
        if self.h_process == 0:
            self.open()

        if KERNEL32.TerminateProcess(self.h_process, 1):
            log.info("Successfully terminated process with pid %d.", self.pid)
            return True
        else:
            log.error("Failed to terminate process with pid %d.", self.pid)
            return False

    def is_64bit(self):
        """Determines if a process is 64bit.
        @return: True if 64bit, False if not
        """
        if self.h_process == 0:
            self.open()

        try:
            val = c_int(0)
            ret = KERNEL32.IsWow64Process(self.h_process, byref(val))
            if ret and not val.value and is_os_64bit():
                return True
        except:
            pass

        return False

    def old_inject(self, dll, apc):
        arg = KERNEL32.VirtualAllocEx(self.h_process,
                                      None,
                                      len(dll) + 1,
                                      MEM_RESERVE | MEM_COMMIT,
                                      PAGE_READWRITE)

        if not arg:
            log.error("VirtualAllocEx failed when injecting process with "
                      "pid %d, injection aborted (Error: %s)",
                      self.pid, get_error_string(KERNEL32.GetLastError()))
            return False

        bytes_written = c_int(0)
        if not KERNEL32.WriteProcessMemory(self.h_process,
                                           arg,
                                           dll + "\x00",
                                           len(dll) + 1,
                                           byref(bytes_written)):
            log.error("WriteProcessMemory failed when injecting process with "
                      "pid %d, injection aborted (Error: %s)",
                      self.pid, get_error_string(KERNEL32.GetLastError()))
            return False

        kernel32_handle = KERNEL32.GetModuleHandleA("kernel32.dll")
        load_library = KERNEL32.GetProcAddress(kernel32_handle, "LoadLibraryA")

        if apc or self.suspended:
            if not self.h_thread:
                log.info("No valid thread handle specified for injecting "
                         "process with pid %d, injection aborted.", self.pid)
                return False

            if not KERNEL32.QueueUserAPC(load_library, self.h_thread, arg):
                log.error("QueueUserAPC failed when injecting process with "
                          "pid %d (Error: %s)",
                          self.pid, get_error_string(KERNEL32.GetLastError()))
                return False
        else:
            new_thread_id = c_ulong(0)
            thread_handle = KERNEL32.CreateRemoteThread(self.h_process,
                                                        None,
                                                        0,
                                                        load_library,
                                                        arg,
                                                        0,
                                                        byref(new_thread_id))
            if not thread_handle:
                log.error("CreateRemoteThread failed when injecting process "
                          "with pid %d (Error: %s)",
                          self.pid, get_error_string(KERNEL32.GetLastError()))
                return False
            else:
                KERNEL32.CloseHandle(thread_handle)

        return True

    def inject(self, dll=None, interest=None, nosleepskip=False):
        """Cuckoo DLL injection.
        @param dll: Cuckoo DLL path.
        @param interest: path to file of interest, handed to cuckoomon config
        @param apc: APC use.
        """
        if not self.pid:
            log.warning("No valid pid specified, injection aborted")
            return False

        thread_id = 0
        if self.thread_id:
            thread_id = self.thread_id

        if not self.is_alive():
            log.warning("The process with pid %s is not alive, "
                        "injection aborted", self.pid)
            return False

        is_64bit = self.is_64bit()
        if not dll:
            if is_64bit:
                dll = "cuckoomon_x64.dll"
            else:
                dll = "cuckoomon.dll"

        dll = randomize_bin(os.path.join("dll", dll), "dll")

        if not dll or not os.path.exists(dll):
            log.warning("No valid DLL specified to be injected in process "
                        "with pid %d, injection aborted.", self.pid)
            return False

        config_path = "C:\\%s.ini" % self.pid
        with open(config_path, "w") as config:
            cfg = Config("analysis.conf")
            cfgoptions = cfg.get_options()

            # start the logserver for this monitored process
            self.logserver = LogServer(cfg.ip, cfg.port, self.logserver_path)

            firstproc = Process.first_process

            config.write("host-ip={0}\n".format(cfg.ip))
            config.write("host-port={0}\n".format(cfg.port))
            config.write("pipe={0}\n".format(PIPE))
            config.write("logserver={0}\n".format(self.logserver_path))
            config.write("results={0}\n".format(PATHS["root"]))
            config.write("analyzer={0}\n".format(os.getcwd()))
            config.write("first-process={0}\n".format("1" if firstproc else "0"))
            config.write("startup-time={0}\n".format(Process.startup_time))
            config.write("file-of-interest={0}\n".format(interest))
            config.write("shutdown-mutex={0}\n".format(SHUTDOWN_MUTEX))
            config.write("terminate-event={0}{1}\n".format(TERMINATE_EVENT, self.pid))
            if nosleepskip:
                config.write("force-sleepskip=0\n")
            elif "force-sleepskip" in cfgoptions:
                config.write("force-sleepskip={0}\n".format(cfgoptions["force-sleepskip"]))
            if "full-logs" in cfgoptions:
                config.write("full-logs={0}\n".format(cfgoptions["full-logs"]))
            if "no-stealth" in cfgoptions:
                config.write("no-stealth={0}\n".format(cfgoptions["no-stealth"]))
            if "norefer" not in cfgoptions:
                config.write("referrer={0}\n".format(get_referrer_url(interest)))
            if firstproc:
                Process.first_process = False

        if thread_id or self.suspended:
            log.debug("Using QueueUserAPC injection.")
        else:
            log.debug("Using CreateRemoteThread injection.")

        orig_bin_name = ""
        bit_str = ""
        if is_64bit:
            orig_bin_name = "loader_x64.exe"
            bit_str = "64-bit"
        else:
            orig_bin_name = "loader.exe"
            bit_str = "32-bit"

        bin_name = randomize_bin(os.path.join("bin", orig_bin_name), "exe")

        if os.path.exists(bin_name):
            ret = subprocess.call([bin_name, "inject", str(self.pid), str(thread_id), dll])
            if ret != 0:
                if ret == 1:
                    log.info("Injected into suspended %s process with pid %d", bit_str, self.pid)
                else:
                    log.error("Unable to inject into %s process with pid %d, error: %d", bit_str, self.pid, ret)
                return False
            else:
                return True
        else:
            log.error("Please place the %s binary from cuckoomon into analyzer/windows/bin in order to analyze %s binaries.", os.path.basename(bin_name), bit_str)
            return False

    def dump_memory(self):
        """Dump process memory.
        @return: operation status.
        """
        if not self.pid:
            log.warning("No valid pid specified, memory dump aborted")
            return False

        if not self.is_alive():
            log.warning("The process with pid %d is not alive, memory "
                        "dump aborted", self.pid)
            return False

        bin_name = ""
        bit_str = ""
        file_path = os.path.join(PATHS["memory"], "{0}.dmp".format(self.pid))

        if self.is_64bit():
            bin_name = "bin/loader_x64.exe"
            bit_str = "64-bit"
        else:
            bin_name = "bin/loader.exe"
            bit_str = "32-bit"

        if os.path.exists(bin_name):
            ret = subprocess.call([bin_name, "dump", str(self.pid), file_path])
            if ret == 1:
                log.info("Dumped %s process with pid %d", bit_str, self.pid)
            else:
                log.error("Unable to dump %s process with pid %d, error: %d", bit_str, self.pid, ret)
                return False
        else:
            log.error("Please place the %s binary from cuckoomon into analyzer/windows/bin in order to analyze %s binaries.", os.path.basename(bin_name), bit_str)
            return False

        nf = NetlogFile(os.path.join("memory", "{0}.dmp".format(self.pid)))
        infd = open(file_path, "rb")
        buf = infd.read(1024*1024)
        try:
            while buf:
                nf.send(buf, retry=False)
                buf = infd.read(1024*1024)
            nf.close()
        except:
            log.warning("Memory dump of process with pid %d failed", self.pid)
            return False

        log.info("Memory dump of process with pid %d completed", self.pid)

        return True
