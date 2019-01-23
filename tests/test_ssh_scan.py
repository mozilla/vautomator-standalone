from lib import target
from lib import ssh_scan


class TestSSHScanTask(object):
    def test_URLtarget(self):
        target = Target("ssh.mozilla.com")
        task = SSHScanTask(target)
        result = task.run()
        # this should fail, but for the sake of example
        assert(result == None)

    # def test_IPv4Target(self):
    #     ipv4 = "10.10.10.10"
    #     assert target.Target(ipv4).valid_ip()

    # def test_FQDNTarget(self):
    #     fqdn = "www.mozilla.org"
    #     assert target.Target(fqdn).valid_fqdn()

    # def test_InvalidTarget(self):
    #     bad_pattern = "192.168.1.1"
    #     assert not target.Target(bad_pattern).isValid()

    #     bad_scheme = "ssh://10.10.10.10"
    #     assert not target.Target(bad_scheme).isValid()

    #     badIPv4 = "300.200.100.1"
    #     assert not target.Target(badIPv4).isValid()

    #     bad_domain = "sodiajdoaijwo"
    #     assert not target.Target(bad_domain).isValid()
