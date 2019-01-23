from lib import target


class TestTarget(object):
    def test_URLtarget(self):
        fqdnurl = "https://www.mozilla.org"
        ipv4url = "http://10.10.10.10"
        assert (target.Target(fqdnurl).isValid() and
                target.Target(ipv4url).isValid())

    def test_IPv4Target(self):
        ipv4 = "10.10.10.10"
        assert target.Target(ipv4).valid_ip()

    def test_FQDNTarget(self):
        fqdn = "infosec.mozilla.org"
        assert target.Target(fqdn).valid_fqdn()

    def test_InvalidTarget(self):
        bad_pattern = "192.168.1.1"
        assert not target.Target(bad_pattern).isValid()

        bad_scheme = "ssh://10.10.10.10"
        assert not target.Target(bad_scheme).isValid()

        badIPv4 = "300.200.100.1"
        assert not target.Target(badIPv4).isValid()

        bad_domain = "sodiajdoaijwo"
        assert not target.Target(bad_domain).isValid()


