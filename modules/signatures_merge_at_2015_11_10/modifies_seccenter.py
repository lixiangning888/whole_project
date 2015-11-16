# -*- coding: utf-8 -*-
# Copyright (C) 2015 Kevin Ross
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class ModifySecurityCenterWarnings(Signature):
    name = "modify_security_center_warnings"
    description = "尝试更改或禁止安全中心报警"
    severity = 3
    categories = ["stealth"]
    authors = ["Kevin Ross"]
    minimum = "1.2"

    def run(self):
        if self.check_write_key(pattern=".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Security\\ Center\\\\.*", regex=True):
            return True

        return False
