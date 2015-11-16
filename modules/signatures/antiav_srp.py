# -*- coding: utf-8 -*-
# Copyright (C) 2014 Accuvant, Inc. (bspengler@accuvant.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AntiAVSRP(Signature):
    name = "antiav_srp"
    description = "更改软件限制策略以破坏反病毒软件"
    severity = 3
    categories = ["anti-av"]
    authors = ["Accuvant"]
    minimum = "1.2"

    def run(self):
        match_key = self.check_write_key(".*\\\\Policies\\\\Microsoft\\\\Windows\\\\Safer\\\\\CodeIdentifiers\\\\0\\\\Paths\\\\.*", regex=True, all=True)
        if match_key:
            for match in match_key:
                self.data.append({"key" : match})
            return True
        return False
