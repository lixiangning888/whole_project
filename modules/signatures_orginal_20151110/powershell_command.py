# Copyright (C) 2015 Kevin Ross, Optiv, Inc. (brad.spengler@optiv.com)
#
# This program is free software: you can redistribute it and/or modify
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

from lib.cuckoo.common.abstracts import Signature

class PowershellCommand(Signature):
    name = "powershell_command"
    description = "Attempts to execute a powershell command with suspicious parameter/s"
    severity = 2
    confidence = 70
    weight = 0
    categories = ["generic"]
    authors = ["Kevin Ross", "Optiv"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.exec_policy = False
        self.user_profile = False
        self.hidden_window = False
        self.b64_encoded = False

    filter_apinames = set(["CreateProcessInternalW","ShellExecuteExW"])

    def on_call(self, call, process):
        if call["api"] == "CreateProcessInternalW":
            cmdline = self.get_argument(call, "CommandLine").lower()
        else:
            filepath = self.get_argument(call, "FilePath").lower()
            params = self.get_argument(call, "Parameters").lower()
            cmdline = filepath + " " + params

        if "powershell.exe" in cmdline and "bypass" in cmdline:
            self.exec_policy = True

        if "powershell.exe" in cmdline and "-nop" in cmdline:
            self.user_profile = True

        if "powershell.exe" in cmdline and "-w" in cmdline and "hidden" in cmdline:
            self.hidden_window = True

        if "powershell.exe" in cmdline and "-enc" in cmdline:
            self.b64_encoded = True

    def on_complete(self):
        if self.exec_policy:
            self.data.append({"execution_policy" : "Attempts to bypass execution policy"})
            self.severity = 3
            self.weight += 1

        if self.user_profile:
            self.data.append({"user_profile" : "Does not load current user profile"})
            self.severity = 3
            self.weight += 1

        if self.hidden_window:
            self.data.append({"hidden_window" : "Attempts to execute command with a hidden window"})
            self.weight += 1

        if self.b64_encoded:
            self.data.append({"b64_encoded" : "Uses a Base64 encoded command value"})
            self.weight += 1

        if self.weight:
            return True
        return False
