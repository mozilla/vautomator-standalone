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


class SSHScanTask(Task):
    def __init__(self, target_obj, port=22):
        super().__init__(target_obj)
        self.port = port

    def run(self):
        if find_executable('ssh_scan'):
            # Found in path, run the command
            # logger.info("[+] Running ssh_scan...")
            cmd = "ssh_scan -t " + self.task_target.targetdomain + " -p " \
                + str(self.ssh_port) + " -o /app/results/" + self.tasktarget.targetdomain \
                + "/ssh_scan.txt"
            sshscan_cmd = utils.sanitise_shell_command(cmd)
            p = subprocess.Popen(sshscan_cmd, stdout=subprocess.PIPE, shell=True)
            p.wait()
            return p
        else:
            logger.error("[-] ssh_scan not found!")
            return False
