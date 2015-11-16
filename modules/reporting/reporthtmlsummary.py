# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import codecs
import base64
import PIL
from PIL import Image
import StringIO

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.objects import File

try:
    from jinja2.environment import Environment
    from jinja2.loaders import FileSystemLoader
    HAVE_JINJA2 = True
except ImportError:
    HAVE_JINJA2 = False

class ReportHTMLSummary(Report):
    """Stores summary report in HTML format."""

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        if not HAVE_JINJA2:
            raise CuckooReportError("Failed to generate summary HTML report: "
                                    "Jinja2 Python library is not installed")

        shots_path = os.path.join(self.analysis_path, "shots")
        if os.path.exists(shots_path):
            shots = []
            counter = 1
            for shot_name in os.listdir(shots_path):
                if not shot_name.endswith(".jpg"):
                    continue

                shot_path = os.path.join(shots_path, shot_name)

                if os.path.getsize(shot_path) == 0:
                    continue

                output = StringIO.StringIO()

                # resize the image to thumbnail size, as weasyprint can't handle resizing
                img = Image.open(shot_path)
                img = img.resize((150, 100), PIL.Image.ANTIALIAS)
                img.save(output, format="JPEG")

                shot = {}
                shot["id"] = os.path.splitext(File(shot_path).get_name())[0]
                shot["data"] = base64.b64encode(output.getvalue())
                shots.append(shot)
                output.close()

                counter += 1

            shots.sort(key=lambda shot: shot["id"])
            results["screenshots"] = shots
        else:
            results["screenshots"] = []

        env = Environment(autoescape=True)
        env.loader = FileSystemLoader(os.path.join(CUCKOO_ROOT,
                                                   "data", "html"))

        try:
            tpl = env.get_template("report.html")
            html = tpl.render({"results": results, "summary_report" : True })
        except Exception as e:
            raise CuckooReportError("Failed to generate summary HTML report: %s" % e)
        
        try:
            with codecs.open(os.path.join(self.reports_path, "summary-report.html"), "w", encoding="utf-8") as report:
                report.write(html)
        except (TypeError, IOError) as e:
            raise CuckooReportError("Failed to write summary HTML report: %s" % e)

        return True
