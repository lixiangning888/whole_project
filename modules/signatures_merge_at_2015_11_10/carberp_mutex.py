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

from lib.cuckoo.common.abstracts import Signature

class CarberpMutexes(Signature):
    name = "carberp_mutex"
    description = "生成常见的Carberp/Rovnix互斥量（mutex）"
    weight = 3
    severity = 3
    categories = ["banker", "trojan", "rootkit"]
    families = ["carberp"]
    authors = ["KillerInstinct"]
    minimum = "0.5"

    def run(self):
        if self.check_mutex(pattern="^(Global\\\\)?(UAC|INS|BD)NTFS\d+$", regex=True):
            return True

        return False
