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

class NetworkSMTP(Signature):
    name = "network_smtp"
    description = "发起SMTP请求,可能被用来发送垃圾邮件"
    severity = 3
    categories = ["smtp", "spam"]
    authors = ["nex"]
    minimum = "0.5"

    def run(self):
        if "network" in self.results:
            if "smtp" in self.results["network"]:
                if len(self.results["network"]["smtp"]) > 0:
                    return True

        return False