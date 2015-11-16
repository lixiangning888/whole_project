# -*- coding: utf-8 -*-
# Copyright (C) 2015 Accuvant Inc. (bspengler@accuvant.com)
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

class ProcessInterest(Signature):
    name = "process_interest"
    description = "对一些具体的运行中的进程呈现出兴趣"
    severity = 2
    categories = ["generic"]
    authors = ["Accuvant"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.searches = 0
        self.lastprocessname = ""
        self.interested_processes = set()

    filter_apinames = set(["Process32NextW", "Process32FirstW"])

    def on_call(self, call, process):
        if call["api"] == "Process32NextW":
            if not call["status"]:
                self.lastprocessname = ""
            else:
                self.lastprocessname = self.get_argument(call, "ProcessName")
        else:
            # is Process32FirstW
            if self.lastprocessname:
                self.interested_processes.add(self.lastprocessname)


    def on_complete(self):
        if self.lastprocessname:
            self.interested_processes.add(self.lastprocessname)
        if len(self.interested_processes):
            for proc in self.interested_processes:
                self.data.append({"process" : proc})
            return True
        return False
