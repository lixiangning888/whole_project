# -*- coding: utf-8 -*-
# Copyright (C) 2015 Kevin Ross
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class DisablesWER(Signature):
    name = "disables_wer"
    description = "尝试禁止系统错误报告（Windows Error Reporting）"
    severity = 3
    categories = ["stealth"]
    authors = ["Kevin Ross"]
    minimum = "1.2"

    def run(self):
        if self.check_write_key(pattern=".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\Windows\\ Error\\ Reporting\\\\Disabled$", regex=True):
            return True

        return False
