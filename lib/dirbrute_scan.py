import logging
import coloredlogs
import subprocess
from lib import utils
from lib.task import Task

# This looks ugly and unnecessary in all files, 
# should implement per module logging
# Logging in UTC
logger = logging.getLogger(__name__)
coloredlogs.install(level='INFO', logger=logger, reconfigure=True,
                    fmt='[%(hostname)s] %(asctime)s %(levelname)-8s %(message)s',
                    datefmt="%Y-%m-%d %I:%M:%S %p %Z")


class DirectoryBruteTask(Task):

    def __init__(self, target_obj, tool="dirb"):
        self.tasktarget = target_obj
        self.toolToRun = tool

    def run(self):
        if (self.toolToRun == "dirb"):
            # dirb is compiled from source, won't be in the PATH
            # Also defaulting to HTTPS URL here
            logger.info("[+] Running dirb scan...")
            if "URL" in self.tasktarget.getType():
                cmd = "/app/vendor/dirb222/dirb " + self.tasktarget.targetname \
                    + "/ /app/vendor/dirb222/wordlists/common.txt -o /app/results/" \
                    + self.tasktarget.targetdomain + "/https_dirb_common.txt -f -w -S -r"
            else:
                cmd = "/app/vendor/dirb222/dirb https://" + self.tasktarget.targetdomain \
                    + "/ /app/vendor/dirb222/wordlists/common.txt -o /app/results/" \
                    + self.tasktarget.targetdomain + "/https_dirb_common.txt -f -w -S -r"
            
            dirbscan_cmd = utils.sanitise_shell_command(cmd)
            p = subprocess.Popen(dirbscan_cmd, stdout=subprocess.PIPE, shell=True)
            p.wait()
            return p
        elif (self.toolToRun == "gobuster"):
            logger.info("[+] Running gobuster scan...")
            if "URL" in self.tasktarget.getType():
                cmd = "go run /app/vendor/gobuster-master/main.go " + self.tasktarget.targetname \
                    + " -w /app/vendor/dirb222/wordlists/common.txt -v -l -o /app/results/" \
                    + self.tasktarget.targetdomain + "/gobuster_common.txt"
            else:
                cmd = "go run /app/vendor/gobuster-master/main.go https://" + self.tasktarget.targetdomain \
                    + " -w /app/vendor/dirb222/wordlists/common.txt -v -l -o /app/results/" \
                    + self.tasktarget.targetdomain + "/gobuster_common.txt"

            gobuster_cmd = utils.sanitise_shell_command(cmd)
            p = subprocess.Popen(gobuster_cmd, stdout=subprocess.PIPE, shell=True)
            p.wait()
            return p
