# -*- coding: utf-8 -*-
# Copyright (C) 2012-2015 KillerInstinct
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

class Office_Macro(Signature):
    name = "office_macro"
    description = "Office文件中包含宏（macro）"
    severity = 2
    categories = ["office"]
    authors = ["KillerInstinct"]
    minimum = "0.5"

    def run(self):
        ret = False
        if "static" in self.results:
            # 97-2003 OLE and 2007+ XML macros
            if "Macro" in self.results["static"]:
                if "Code" in self.results["static"]["Macro"]:
                    ret = True
                    total = len(self.results["static"]["Macro"]["Code"])
                    if total > 1:
                        self.description = " Office文件包含了 %s 个 macros." % str(total)
            # 97-2003 XML macros
            if not ret and "strings" in self.results:
                header = False
                for line in self.results["strings"]:
                    if "<?xml" in line:
                        header = True
                    if header and 'macrosPresent="yes"' in line:
                        ret = True
                        self.description = " Office文件包含了一个基于 MSO/ActiveMime 的macro "
                        self.severity = 3
                        break

        # Check for known lures
        if ret and "strings" in self.results:
            lures = ["bank account",
                     "enable content",
                     "tools > macro",
                     "macros must be enabled",
                     "enable macro",
                    ]
            positives = list()
            for string in self.results["strings"]:
                for lure in lures:
                    if lure in string.lower():
                        if string not in positives:
                            positives.append(string)
                            self.weight += 1

            if positives != []:
                self.severity = 3
                self.description += " 文件还包含常见钓鱼(phishing)欺诈相关字符串 "
                for positive in positives:
                    self.data.append({"Lure": positive})

        # Increase severity on empty documents with macros
        if ret and "static" in self.results:
            if "Metadata" in self.results["static"]:
                if "SummaryInformation" in self.results["static"]["Metadata"]:
                    words = self.results["static"]["Metadata"]["SummaryInformation"]["num_words"]
                    if words == "0":
                        self.severity = 3
                        self.weight += 2
                        self.description += " 文件无内容 "

        return ret
