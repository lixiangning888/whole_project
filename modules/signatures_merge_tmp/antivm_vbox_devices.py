# -*- coding: utf-8 -*-
# Copyright (C) 2012 Claudio "nex" Guarnieri (@botherder)
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

class VBoxDetectDevices(Signature):
    name = "antivm_vbox_devices"
    description = "通过设备检测VirtualBox系统"
    severity = 3
    categories = ["anti-vm"]
    authors = ["nex"]
    minimum = "1.2"

    def run(self):
        indicators = [
            ".*\\VBoxGuest$",
            ".*\\VBoxMouse$",
            ".*\\VBoxVideo$",
            ".*\\VBoxMiniRdrDN$",
            ".*\\VBoxTrayIPC$",
        ]

        for indicator in indicators:
            if self.check_file(pattern=indicator):
                return True

        return False
