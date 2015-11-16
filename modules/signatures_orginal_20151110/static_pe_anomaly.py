﻿# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature
from datetime import datetime

class PEAnomaly(Signature):
    name = "static_pe_anomaly"
    description = "Anomalous binary characteristics"
    severity = 3
    confidence = 80
    weight = 0
    categories = ["static"]
    authors = ["Optiv"]
    minimum = "1.2"

    def run(self):
        # set the bad date to a year prior to the release date of the OS
        bad_date_map = {
            # version , year, month
            "4.0" :  (1995, 6),
            "5.0" : (1999, 2),
            "5.1" : (2000, 10),
            "5.2" : (2002, 3),
            "6.0" : (2005, 11), 
            "6.1" : (2008, 10),
            "6.2" : (2011, 9),
            "6.3" : (2012, 10),
            "10.0" : (2014, 6),
        }
        found_sig = False

        if not "static" in self.results or not "pe" in self.results["static"]:
            return False

        compiletime = datetime.strptime(self.results["static"]["pe"]["timestamp"], '%Y-%m-%d %H:%M:%S')
        osver = self.results["static"]["pe"]["osversion"]
        osmajor = int(osver.split(".")[0], 10)
        if osmajor < 4 and compiletime.year >= 2000:
            self.data.append({"anomaly" : "Minimum OS version is older than NT4 yet the PE timestamp year is newer than 2000"})
            self.weight += 1
                           
        # throw out empty timestamps
        if compiletime.year > 1970 and osver in bad_date_map:
            if compiletime.year < bad_date_map[osver][0] or (compiletime.year == bad_date_map[osver][0] and compiletime.month < bad_date_map[osver][1]):
                self.data.append({"anomaly" : "Timestamp on binary predates the release date of the OS version it requires by at least a year"})
                self.weight += 1

        if "sections" in self.results["static"]["pe"]:
            bigvirt = False
            unprint = False
            foundsec = None
            foundcodesec = False
            foundnamedupe = False
            lowrva = 0xffffffff
            imagebase = int(self.results["static"]["pe"]["imagebase"], 16)
            eprva = int(self.results["static"]["pe"]["entrypoint"], 16) - imagebase
            seennames = set()
            for section in self.results["static"]["pe"]["sections"]:
                if section["name"] in seennames:
                    foundnamedupe = True
                seennames.add(section["name"])
                if "IMAGE_SCN_CNT_CODE" in section["characteristics"]:
                    foundcodesec = True
                if "\\x" in section["name"]:
                    unprint = True
                secstart = int(section["virtual_address"], 16)
                secend = secstart + int(section["virtual_size"], 16)

                if (secend - secstart) >= 100 * 1024 * 1024:
                    bigvirt = True

                # seconds are mapped first to last, so the last section matched is the correct one
                if eprva >= secstart and eprva < secend:
                    foundsec = section
                if secstart < lowrva:
                    lowrva = secstart
            if foundnamedupe:
                self.data.append({"anomaly" : "Found duplicated section names"})
                self.weight += 1
            if unprint:
                self.data.append({"anomaly" : "Unprintable characters found in section name"})
                self.weight += 1
            if not foundsec and foundcodesec:
                # we check for code sections to not FP on resource-only DLLs where the EP RVA will be 0
                self.data.append({"anomaly" : "Entrypoint of binary is located outside of any mapped sections"})
                self.weight += 1
            if foundsec and "IMAGE_SCN_MEM_EXECUTE" not in foundsec["characteristics"]:
                # Windows essentially turns DEP off in this case, but it was only seen (as far as named packers go) in
                # one instance I could think of years ago in a rare packer
                self.data.append({"anomaly" : "Entrypoint of binary points to a non-executable code section"})
                self.weight += 1
            if bigvirt:
                # used to blow up memory dumpers
                self.data.append({"anomaly" : "Contains a section with a virtual size >= 100MB"})
                self.weight += 1
        if "resources" in self.results["static"]["pe"]:
            for resource in self.results["static"]["pe"]["resources"]:
                if int(resource["size"], 16) >= 100 * 1024 * 1024:
                    self.data.append({"anomaly" : "Contains a resource with a size >= 100MB"})
                    self.weight += 1
        if "reported_checksum" in self.results["static"]["pe"] and "actual_checksum" in self.results["static"]["pe"]:
            reported = int(self.results["static"]["pe"]["reported_checksum"], 16)
            actual = int(self.results["static"]["pe"]["actual_checksum"], 16)
            if reported and reported != actual:
                self.data.append({"anomaly" : "Actual checksum does not match that reported in PE header"})
                self.weight += 1

        if self.weight:
            return True
        return False
