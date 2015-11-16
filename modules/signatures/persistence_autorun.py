# -*- coding: utf-8 -*-
# Copyright (C) 2012,2014,2015 Michael Boman (@mboman), Accuvant, Inc. (bspengler@accuvant.com)
#
# This program is free Software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Based on information from http://antivirus.about.com/od/windowsbasics/tp/autostartkeys.htm

# Additional keys added from SysInternals Administrators Guide

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class Autorun(Signature):
    name = "persistence_autorun"
    description = "将自己装载到Windows开机自动启动项目"
    severity = 3
    categories = ["persistence"]
    authors = ["Michael Boman", "nex", "securitykitten", "Accuvant", "KillerInstinct"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.registry_writes = dict()
        self.found_autorun = False

    filter_apinames = set(["RegSetValueExA", "RegSetValueExW", "NtSetValueKey", "CreateServiceA", "CreateServiceW"])

    def on_call(self, call, process):
        if call["api"].startswith("CreateService") and call["status"]:
            starttype = int(self.get_argument(call, "StartType"), 10)
            servicename = self.get_argument(call, "ServiceName")
            binpath = self.get_argument(call, "BinaryPathName")
            if starttype < 3:
                self.data.append({"service name" : servicename })
                self.data.append({"service path" : binpath })
                self.found_autorun = True
        elif call["status"]:
            fullname = self.get_argument(call, "FullName")
            self.registry_writes[fullname] = self.get_argument(call, "Buffer")

    def on_complete(self):
        indicators = [
            ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\.*",
            ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce\\\\.*",
            ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServices\\\\.*",
            ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnceEx\\\\.*",
            ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServicesOnce\\\\.*",
            ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Winlogon\\\\Notify\\\\.*",
            ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Winlogon\\\\Userinit$",
            ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\Run\\\\.*",
            ".*\\\\Microsoft\\\\Active\\ Setup\\\\Installed Components\\\\.*",
            ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Windows\\\\AppInit_DLLs$",
            ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\SharedTaskScheduler\\\\.*",
            ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Image\\ File\\ Execution\\ Options\\\\[^\\\\]*\\\\\Debugger$",
            ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Winlogon\\\\Shell$",
            ".*\\\\System\\\\(CurrentControlSet|ControlSet001)\\\\Services\\\\[^\\\\]*\\\\ImagePath$",
            ".*\\\\System\\\\(CurrentControlSet|ControlSet001)\\\\Services\\\\[^\\\\]*\\\\Parameters\\\\ServiceDLL$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\Exefile\\\\Shell\\\\Open\\\\Command\\\\\(Default\)$",
            ".*\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows\\\\load$",
            ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\ShellServiceObjectDelayLoad\\\\.*",
            ".*\\\\System\\\\(CurrentControlSet|ControlSet001)\\\\Control\\\\Session\\ Manager\\\\AppCertDlls\\\\.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\clsid\\\\[^\\\\]*\\\\InprocServer32\\\\.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\clsid\\\\[^\\\\]*\\\\LocalServer32\\\\.*"
            ]
        whitelists = [
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\clsid\\\\{CAFEEFAC-0017-0000-FFFF-ABCDEFFEDCBA}\\\\InprocServer32\\\\.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\clsid\\\\[^\\\\]*\\\\InprocServer32\\\\ThreadingModel$"
            ]

        for indicator in indicators:
            match_key = self.check_write_key(pattern=indicator, regex=True, all=True)
            if match_key:
                for match in match_key:
                    in_whitelist = False
                    for entry in whitelists:
                        if re.match(entry, match, re.IGNORECASE):
                            in_whitelist = True
                            break

                    if not in_whitelist:
                        data = self.registry_writes.get(match, "unknown")
                        if data.lower() != "c:\\program files\\java\\jre7\\bin\jp2iexp.dll":
                            self.data.append({"key" : match})
                            self.data.append({"data" : data})
                            self.found_autorun = True

        indicators = [
            ".*\\\\win\.ini$",
            ".*\\\\system\.ini$",
            ".*\\\\Start Menu\\\\Programs\\\\Startup\\\\.*",
            ".*\\\\WINDOWS\\\\Tasks\\\\.*"
        ]

        for indicator in indicators:
            match_file = self.check_write_file(pattern=indicator, regex=True, all=True)
            if match_file:
                for match in match_file:
                    self.data.append({"file" : match})
                self.found_autorun = True

        taskpat = ".*schtasks(\.exe)?.*/CREATE.*/SC\s+(ONLOGON|ONSTART).*"
        tasked = self.check_executed_command(pattern=taskpat, regex=True)
        if tasked:
            self.found_autorun = True
            self.data.append({"task": tasked})

        return self.found_autorun