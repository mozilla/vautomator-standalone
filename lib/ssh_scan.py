from distutils.spawn import find_executable


class SSHScanTask():
    def __init__(self, target, port=22):
        self.target = target
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
