from distutils.spawn import find_executable
import logging
import coloredlogs
import subprocess
from lib import utils, task

# This looks ugly and unnecessary in all files, 
# should implement per module logging
logger = logging.getLogger(__name__)
coloredlogs.install(level='INFO', logger=logger, reconfigure=True,
                    fmt='[%(hostname)s] %(asctime)s %(levelname)-8s %(message)s',
                    datefmt="%Y-%m-%d %I:%M:%S %p %Z")


class MozillaTLSObservatoryTask(task):

    def __init__(self, target_obj):
        super().__init__(target_obj)

    def run(self):
        if find_executable('tlsobs'):
            # Found in path, run the command
            logger.info("[+] Running TLS Observatory scan...")
            cmd = "tlsobs -r -raw " + self.tasktarget.targetname \
                + " > /app/results/" + self.tasktarget.targetdomain \
                + "/tlsobs_scan.txt"
            tlsobs_cmd = utils.sanitise_shell_command(cmd)
            p = subprocess.Popen(tlsobs_cmd, stdout=subprocess.PIPE, shell=True)
            p.wait()
            return p
        else:
            logger.error("[-] TLS Observatory not found in Docker image!")
            return False
