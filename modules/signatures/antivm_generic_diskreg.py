# -*- coding: utf-8 -*-
# Copyright (C) 2012,2015 Claudio "nex" Guarnieri (@botherder), Accuvant, Inc. (bspengler@accuvant.com)
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

class AntiVMDiskReg(Signature):
    name = "antivm_generic_diskreg"
    description = "检查注册表中的磁盘驱动器，可能被用来实现反虚拟机"
    severity = 3
    confidence = 50
    categories = ["anti-vm"]
    authors = ["nex"]
    minimum = "0.5"

    def run(self):
        indicators = [
            ".*\\\\SYSTEM\\\\(CurrentControlSet|ControlSet001)\\\\Enum\\\\IDE$",
            ".*\\\\SYSTEM\\\\(CurrentControlSet|ControlSet001)\\\\Services\\\\Disk\\\\Enum\\\\.*",
            ]
        for indicator in indicators:
            if self.check_key(pattern=indicator, regex=True):
                return True
        return False