# -*- coding: utf-8 -*-
# Copyright (C) 2015 Accuvant, Inc. (bspengler@accuvant.com)
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

class SuricataAlert(Signature):
    name = "suricata_alert"
    description = "生成可疑网络流量，可能被用来进行恶意活动"
    severity = 3
    confidence = 80
    weight = 3
    categories = ["network"]
    authors = ["Accuvant"]
    minimum = "1.2"

    def run(self):
        sigset = set()
        whitelist = [
            "Application Crash Report Sent to Microsoft",
            "Outdated Windows Flash Version IE",
        ]
        if "suricata" in self.results:
            if "alerts" in self.results["suricata"]:
                for alert in self.results["suricata"]["alerts"]:
                    if "signature" in alert:
                        addsig = True
                        for item in whitelist:
                            if item in alert["signature"]:
                                addsig = False
                                break
                        if addsig:
                            sigset.add(alert["signature"])
        for sig in sigset:
            self.data.append({"signature" : sig})
            self.weight += 1
        if len(sigset):
            return True
        return False
