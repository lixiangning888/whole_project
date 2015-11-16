# Copyright (C) 2014 Accuvant, Inc. (bspengler@accuvant.com)
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

class VMwareDetectFiles(Signature):
    name = "antivm_vmware_files"
    description = "Detects VMware through the presence of a file"
    severity = 3
    categories = ["anti-vm"]
    authors = ["Accuvant"]
    minimum = "1.2"

    def run(self):
        indicators = [
            ".*\\\\drivers\\\\vmmouse\.sys$",
            ".*\\\\drivers\\\\vmhgfs\.sys$",
            ".*\\\\VMware\\ Tools\\\\TPAutoConnSvc.exe$",
            ".*\\\\VMware\\ Tools\\\\TPAutoConnSvc.exe.dll$",
        ]

        for indicator in indicators:
            if self.check_file(pattern=indicator, regex=True):
                return True

        return False
