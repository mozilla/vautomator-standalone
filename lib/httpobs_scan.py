from distutils.spawn import find_executable
import logging
import coloredlogs
import subprocess
from lib import utils
from lib.task import Task

# This looks ugly and unnecessary in all files, 
# should implement per module logging
logger = logging.getLogger(__name__)
coloredlogs.install(level='INFO', logger=logger, reconfigure=True,
                    fmt='[%(hostname)s] %(asctime)s %(levelname)-8s %(message)s',
                    datefmt="%Y-%m-%d %I:%M:%S %p %Z")


class MozillaHTTPObservatoryTask(Task):

    def __init__(self, target_obj):
        self.tasktarget = target_obj

    def run(self):
        if "IPv4" in self.tasktarget.type:
            # HTTP Observatory only accepts FQDN
            return False

        if find_executable('observatory'):
            # Found in path, run the command
            logger.info("[+] Running HTTP Observatory scan...")
            cmd = "observatory --format=report -z --rescan " \
                + self.tasktarget.targetdomain + " > /app/results/" \
                + self.tasktarget.targetdomain + "/httpobs_scan.txt"
            observatory_cmd = utils.sanitise_shell_command(cmd)
            p = subprocess.Popen(observatory_cmd, stdout=subprocess.PIPE, shell=True)
            p.wait()
            return p

        else:
            logger.error("[-] HTTP Observatory not found in Docker image!")
            return False
