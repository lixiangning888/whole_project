# Copyright (C) 2014 Accuvant, Inc. (bspengler@accuvant.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
from lib.cuckoo.common.abstracts import Signature

class KeyLogger(Signature):
    name = "infostealer_keylog"
    description = "Sniffs keystrokes"
    severity = 3
    categories = ["infostealer"]
    authors = ["Accuvant"]
    minimum = "1.2"
    evented = True

    filter_apinames = set(["SetWindowsHookExA","SetWindowsHookExW","GetAsyncKeyState"])

    def on_call(self, call, process):
        if call["api"] == "GetAsyncKeyState":
            # avoid an IE false positive
            keycode = int(self.get_argument(call, "KeyCode"), 10)
            # whitelist a-z, 0-9
            if (keycode >= 0x30 and keycode <= 0x39) or (keycode >= 0x4a and keycode <= 0x5a):
                return True
        else:
            id = int(self.get_argument(call, "HookIdentifier"), 10)
            thread = int(self.get_argument(call, "ThreadId"), 10)

            # global WH_KEYBOARD or WH_KEYBOARD_LL hook
            if thread == 0 and (id == 2 or id == 13):
                return True
