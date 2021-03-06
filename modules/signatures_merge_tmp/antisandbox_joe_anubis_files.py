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

class SandboxJoeAnubisDetectFiles(Signature):
    name = "antisandbox_joe_anubis_files"
    description = "通过文件检测是否存在Joe或Anubis沙盒扫描系统"
    severity = 3
    categories = ["anti-sandbox"]
    authors = ["Kevin Ross"]
    minimum = "0.5"

    def run(self):
        indicators = [
            "C\:\\\\sample\.exe$",
            "C\:\\\\InsideTm\\\\.*",
        ]

        for indicator in indicators:
            if self.check_file(pattern=indicator, regex=True):
                return True

        return False
