# -*- coding: utf-8 -*-
# Copyright (C) 2015 KillerInstinct
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

try:
    import re2 as re
except:
    import re

from lib.cuckoo.common.abstracts import Signature

class Secure_Login_Phish(Signature):
    name = "secure_login_phish"
    description = "HTML标题包含’安全登录(Secure Login)’,但连接并非HTTPS，常见于网络欺诈"
    severity = 2
    categories = ["phish"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lasturl = str()
        self.phishurls = set()

    filter_apinames = set(["InternetCrackUrlW", "InternetReadFile"])

    def on_call(self, call, process):
        if call["api"] == "InternetCrackUrlW":
            url = self.get_argument(call, "Url")
            if url:
                self.lasturl = url
        elif call["api"] == "InternetReadFile":
            buf = self.get_argument(call, "Buffer")
            if buf and not self.lasturl.startswith("https"):
                if "<title>" in buf:
                    if re.search("<title>\s*Secure\s*Login\s*</title>", buf, re.I):
                        self.phishurls.add(self.lasturl)

    def on_complete(self):
        if self.phishurls:
            for url in self.phishurls:
                self.data.append({"URL": url})
            return True

        return False
