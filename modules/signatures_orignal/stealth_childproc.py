# Copyright (C) 2014 Accuvant, Inc. (bspengler@accuvant.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class StealthChildProc(Signature):
    name = "stealth_childproc"
    description = "Forces a created process to be the child of an unrelated process"
    severity = 3
    categories = ["stealth"]
    authors = ["Accuvant"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["NtCreateProcess","NtCreateProcessEx","RtlCreateUserProcess","CreateProcessInternalW"])

    def on_call(self, call, process):
        parenthandle = self.get_argument(call, "ParentHandle")
        if parenthandle and parenthandle != "0xffffffff":
            return True
