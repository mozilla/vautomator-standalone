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


class MozillaTLSObservatoryTask(Task):

    def __init__(self, target):
        self.target = target

    def run(self):
        if find_executable('tlsobs'):
            # Found in path, run the command
            logger.info("[+] Running TLS Observatory scan...")
            cmd = "tlsobs -r -raw " + self.target.targetname \
                + " > /app/results/" + self.target.targetdomain \
                + "/tlsobs_scan.txt"
            cmd = utils.sanitise_shell_command(cmd)
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            p.wait()
            return p
        else:
            logger.error("[-] TLS Observatory not found in Docker image!")
            return False