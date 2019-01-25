from lib.target import Target
from lib.ssh_scan import SSHScanTask
import json


class TestSSHScanTask(object):
    def test_SSHScan(self):
        target = Target("ssh.mozilla.com")
        task = SSHScanTask(target)
        result = task.run()
        stdout, _ = result.communicate()
        result_list = json.loads(stdout.decode('utf8'))
        assert('grade' in result_list[0]['compliance'])
