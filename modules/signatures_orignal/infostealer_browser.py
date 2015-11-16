# Copyright (C) 2012-2015 Claudio "nex" Guarnieri (@botherder), Accuvant, Inc. (bspengler@accuvant.com)
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

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class BrowserStealer(Signature):
    name = "infostealer_browser"
    description = "Steals private information from local Internet browsers"
    severity = 3
    confidence = 30
    categories = ["infostealer"]
    authors = ["nex", "Accuvant"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.filematches = set()
        self.saw_stealer = False

    indicators = [
        re.compile(".*\\\\Mozilla\\\\Firefox\\\\Profiles\\\\.*\\\\.default\\\\signons\.sqlite$", re.I),
        re.compile(".*\\\\Mozilla\\\\Firefox\\\\Profiles\\\\.*\\\\.default\\\\secmod\.db$", re.I),
        re.compile(".*\\\\Mozilla\\\\Firefox\\\\Profiles\\\\.*\\\\.default\\\\cert8\.db$", re.I),
        re.compile(".*\\\\Mozilla\\\\Firefox\\\\Profiles\\\\.*\\\\.default\\\\key3\.db$", re.I),
        re.compile(".*\\\\History\\\\History\.IE5\\\\index\.dat$", re.I),
        re.compile(".*\\\\Cookies\\\\.*", re.I),
        re.compile(".*\\\\Temporary\\ Internet\\ Files\\\\Content\.IE5\\\\index\.dat$", re.I),
        re.compile(".*\\\\Application\\ Data\\\\Google\\\\Chrome\\\\.*", re.I),
        re.compile(".*\\\\Application\\ Data\\\\Mozilla\\\\Firefox\\\\.*", re.I),
        re.compile(".*\\\\Application\\ Data\\\\Opera\\\\.*", re.I),
        re.compile(".*\\\\Application\\ Data\\\\Chromium\\\\.*", re.I),
        re.compile(".*\\\\Application\\ Data\\\\ChromePlus\\\\.*", re.I),
        re.compile(".*\\\\Application\\ Data\\\\Nichrome\\\\.*", re.I),
        re.compile(".*\\\\Application\\ Data\\\\Bromium\\\\.*", re.I),
        re.compile(".*\\\\Application\\ Data\\\\RockMelt\\\\.*", re.I)

    ]
    filter_apinames = set(["NtReadFile", "CopyFileA", "CopyFileW", "CopyFileExW"])

    def on_call(self, call, process):
        # If the current process appears to be a browser, continue.
        # TODO: implement better checks here -- the malware can be named whatever it wants or can
        # inject into browser processes
        if process["process_name"].lower() in ("iexplore.exe", "firefox.exe", "chrome.exe"):
            return None

        filename = None
        if call["api"] == "NtReadFile":
            filename = self.get_argument(call, "HandleName")
        else:
            filename = self.get_argument(call, "ExistingFileName")
        if not filename:
            return None

        for indicator in self.indicators:
            if indicator.match(filename):
                self.filematches.add(filename)
                self.saw_stealer = True

    def on_complete(self):
        for file in self.filematches:
            self.data.append({"file" : file })
        return self.saw_stealer
