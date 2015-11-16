# -*- coding: utf-8 -*-
# Copyright (C) 2013 Claudio "nex" Guarnieri (@botherder)
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

class BitcoinOpenCL(Signature):
    name = "bitcoin_opencl"
    description = "安装OpenCL库，可能被用来挖取比特币"
    severity = 2
    categories = ["bitcoin"]
    authors = ["nex"]
    minimum = "0.5"

    def run(self):
        if self.check_file(pattern=".*OpenCL\.dll$", regex=True):
            return True

        return False
