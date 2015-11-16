# -*- coding: utf-8 -*-
# Copyright (C) 2015 Will Metcalf william.metcalf@gmail.com 
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

class BrowserScanbox(Signature):
    name = "browser_scanbox"
    description = "浏览器中存在Scanbox活动"
    weight = 3
    severity = 3
    categories = ["exploit"]
    authors = ["Will Metcalf"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_categories = set(["browser"])
    # backward compat
    filter_apinames = set(["JsEval", "COleScript_Compile", "COleScript_ParseScriptText"])

    def on_call(self, call, process):
        if call["api"] == "JsEval":
            buf = self.get_argument(call, "Javascript")
        else:
            buf = self.get_argument(call, "Script")
            if 'softwarelist.push(' in buf.lower() and 'indexof("-2147023083")' in buf.lower():
                return True
            elif 'var logger' in buf.lower() and 'document.onkeypress = keypress;' in buf.lower() and 'setinterval(sendchar,' in buf.lower():
                return True
