# -*- coding: utf-8 -*-
# Copyright (C) 2015 Kevin Ross
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

class BrowserAddon(Signature):
    name = "browser_addon"
    description = "安装浏览器插件或扩展组件"
    severity = 2
    categories = ["browser", "adware"]
    authors = ["Kevin Ross"]
    minimum = "1.2"

    def run(self):
        reg_indicators = [
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Internet\\ Explorer\\\\Toolbar\\\\.*",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Mozilla\\\\Firefox\\\\Extensions\\\\.*",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?MozillaPlugins\\\\.*",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Google\\\\Chrome\\\\Extensions\\\\.*",
        ]
        found = False
        for indicator in reg_indicators:
            reg_match = self.check_write_key(pattern=indicator, regex=True, all=True)
            if reg_match:
                for match in reg_match:
                    self.data.append({"key" : match })
                found = True
        return found
