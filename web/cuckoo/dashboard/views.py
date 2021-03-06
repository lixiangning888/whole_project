# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys
import time

from django.conf import settings
from django.template import RequestContext
from django.http import HttpResponse
from django.shortcuts import render_to_response
from django.views.decorators.http import require_safe

import pymongo

sys.path.append(settings.CUCKOO_PATH)

from lib.cuckoo.core.database import Database, TASK_PENDING, TASK_RUNNING
from lib.cuckoo.core.database import TASK_COMPLETED, TASK_RECOVERED
from lib.cuckoo.core.database import TASK_REPORTED, TASK_FAILED_ANALYSIS
from lib.cuckoo.core.database import TASK_FAILED_PROCESSING, TASK_FAILED_REPORTING

from django.contrib.auth.decorators import login_required

import pprint
pp = pprint.PrettyPrinter()

results_db = pymongo.MongoClient(settings.MONGO_HOST, settings.MONGO_PORT)[settings.MONGO_DB]

def timestamp(dt):
    """Returns the timestamp of a datetime object."""
    if not dt: return None
    return time.mktime(dt.timetuple())
@login_required
@require_safe
def index(request):
    db = Database()
    report = dict(
        total_file=results_db.analysis.find({'info.category':'file'}).count(),
        total_url=results_db.analysis.find({'info.category':'url'}).count(),
        recent_files=results_db.analysis.find({'info.category':'file'},{"target":1,"malscore":1},sort=[("info.ended", pymongo.DESCENDING)]).limit(10),
        recent_urls=results_db.analysis.find({'info.category':'url'},{"target":1,"malscore":1},sort=[("info.ended", pymongo.DESCENDING)]).limit(10),
        total_samples=db.count_samples(),
        total_tasks=db.count_tasks(),
        states_count={},
        estimate_hour=None,
        estimate_day=None
    )

    states = (
        TASK_PENDING,
        TASK_RUNNING,
        TASK_COMPLETED,
        TASK_RECOVERED,
        TASK_REPORTED,
        TASK_FAILED_ANALYSIS,
        TASK_FAILED_PROCESSING,
        TASK_FAILED_REPORTING
    )

    for state in states:
        report["states_count"][state] = db.count_tasks(state)

    offset = None

    # For the following stats we're only interested in completed tasks.
    tasks = db.list_tasks(offset=offset, status=TASK_COMPLETED)
    tasks += db.list_tasks(offset=offset, status=TASK_REPORTED)

    if tasks:
        # Get the time when the first task started.
        started = min(timestamp(task.started_on) for task in tasks)

        # Get the time when the last task completed.
        completed = max(timestamp(task.completed_on) for task in tasks)

        # Get the amount of tasks that actually completed.
        finished = len(tasks)

        hourly = 60 * 60 * finished / (completed - started)

        report["estimate_hour"] = int(hourly)
        report["estimate_day"] = int(24 * hourly)

    return render_to_response("dashboard/index.html",
                              {"report" : report},
                              context_instance=RequestContext(request))
