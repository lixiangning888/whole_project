# Copyright (C) 2015 KillerInstinct, Accuvant, Inc. (bspengler@accuvant.com)
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

class RansomwareFiles(Signature):
    name = "ransomware_files"
    description = "Created known ransomware decryption instruction / key file."
    weight = 3
    severity = 3
    categories = ["ransomware"]
    authors = ["KillerInstinct"]
    minimum = "1.2"

    def run(self):
        # Lower-case file names
        file_list = [
            ".*\\\\help_decrypt.html$",
            ".*\\\\decrypt_instruction.html$",
            ".*\\\\decrypt_instructions.txt$",
            ".*\\\\vault.key$",
            ".*\\\\vault.txt$",
            ".*\\\\!Decrypt-All-Files.*.txt$",
            ".*\\\\!Decrypt-All-Files.*.bmp$",
            ".*\\\\help_restore_files.txt$",
            ".*\\\\help_to_save_files.txt$",
            ".*\\\\help_to_save_files.bmp$",
            ".*\\\\recovery_file.txt$",
            ".*\\\\recovery_key.txt$",
        ]

        for file in file_list:
            if self.check_write_file(pattern=file, regex=True):
                return True

        return False
