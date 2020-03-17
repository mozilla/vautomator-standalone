from distutils.spawn import find_executable
import logging
import coloredlogs
import subprocess
from lib import utils
from lib.task import Task
from lib.target import Target
from lib.tlsobs_scan import MozillaTLSObservatoryTask


class TestMozillaTLSObservatoryTask(object):
    def test_run(self):
        fqdn = "www.mozilla.org"
        target = Target(fqdn)
        task = MozillaTLSObservatoryTask(target)

        assert (task.run == "insert something we want to assert about task")
