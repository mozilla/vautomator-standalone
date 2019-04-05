import socket
import logging
import coloredlogs
import datetime
from netaddr import valid_ipv4
from urllib.parse import urlparse
from lib import task

# Logging in UTC
logger = logging.getLogger(__name__)
coloredlogs.install(
    level="INFO",
    logger=logger,
    reconfigure=True,
    fmt="[%(hostname)s] %(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %I:%M:%S %p %Z",
)


class Target:

    # Here, tasklist is a list of Task objects
    def __init__(self, target, results_dict={}):
        self.targetname = target
        self.targetdomain = ""
        self.type = ""
        self.tasklist = []
        self.resultsdict = results_dict

    def isValid(self):
        # A target can be 4 things:
        # 1. FQDN
        # 2. IPv4 address
        # 3. URL with a hostname
        # 4. URL with IPv4 address

        if not isinstance(self.targetname, str):
            return False

        starts_with_anti_patterns = ["127.0.0", "10.", "172.", "192.168", "169.254.169.254"]

        for pattern in starts_with_anti_patterns:
            if self.targetname.startswith(pattern):
                return False

        if self.valid_ip():
            self.type = "IPv4"
            self.targetdomain = self.targetname
            return True
        elif self.valid_fqdn():
            self.type = "FQDN"
            self.targetdomain = self.targetname
            return True
        else:
            if "http" in self.targetname:
                orig_target = self.targetname
                self.targetname = urlparse(self.targetname).netloc
                if self.valid_ip():
                    self.type = "IPv4|URL"
                    self.targetdomain = self.targetname
                    self.targetname = orig_target
                elif self.valid_fqdn():
                    self.type = "FQDN|URL"
                    self.targetdomain = self.targetname
                    self.targetname = orig_target
                else:
                    return False
                return True
            else:
                return False
            return False

    def getType(self):
        return self.type

    def valid_ip(self):
        if valid_ipv4(self.targetname):
            self.type = "IPv4"
            return True
        return False

    def valid_fqdn(self):
        try:
            socket.gethostbyname(self.targetname)
            self.type = "FQDN"
            return True
        except Exception:
            return False

    def addTask(self, new_task):
        # This is a hacky way pf running ssh_scan
        # right after nmap port scan
        if isinstance(new_task, task.SSHScanTask):
            self.tasklist.insert(2, new_task)
        else:
            self.tasklist.insert(len(self.tasklist), new_task)

    def runTasks(self):
        fresh_nessus = None

        for one_task in self.tasklist:

            if isinstance(one_task, task.NmapTask):
                nmap_results = one_task.runNmapScan()
                if nmap_results:
                    logger.info("[+] Nmap port scan(s) successfully ran.")
                    self.resultsdict.update({"nmap": True})

            elif isinstance(one_task, task.NessusTask):
                nessus_results = one_task.runNessusScan()
                if nessus_results:
                    self.resultsdict.update({"nessus": True})
                    epoch_cdate = nessus_results.last_history().creation_date
                    cdate = datetime.datetime.fromtimestamp(float(epoch_cdate))
                    # Checking the creation day of the scan to see if it's
                    # older than 15 days, if older this is a new scan
                    if (datetime.date.today() - cdate.date() < datetime.timedelta(days=15)):
                        fresh_nessus = nessus_results
                        nessus_task = one_task

            elif isinstance(one_task, task.MozillaTLSObservatoryTask):
                tlsobs_results = one_task.runTLSObsScan()
                if tlsobs_results and tlsobs_results.returncode == 0:
                    logger.info("[+] TLS Observatory scan successfully ran.")
                    self.resultsdict.update({"tlsobs": True})

            elif isinstance(one_task, task.MozillaHTTPObservatoryTask):
                httpobs_results = one_task.runHttpObsScan()
                # 0 is the returncode for successful execution
                if httpobs_results and httpobs_results.returncode == 0:
                    logger.info("[+] HTTP Observatory scan successfully ran.")
                    self.resultsdict.update({"httpobs": True})

            elif isinstance(one_task, task.WebSearchTask):
                websearch_results = one_task.runWebSearchScan()
                if websearch_results:
                    logger.info("[+] WebSearch scan successfully ran.")
                    self.resultsdict.update({"websearch": True})

            elif isinstance(one_task, task.SSHScanTask):
                sshscan_results = one_task.runSSHScan()
                if sshscan_results and sshscan_results.returncode == 0:
                    logger.info("[+] SSH scan successfully ran.")
                    self.resultsdict.update({"sshscan": True})

            elif isinstance(one_task, task.DirectoryBruteTask):
                dirbrute_results = one_task.runDirectoryBruteScan()
                if dirbrute_results and dirbrute_results.returncode == 0:
                    logger.info("[+] Directory brute scan successfully ran.")
                    self.resultsdict.update({"dirbrute": True})
                else:
                    self.resultsdict.update({"dirbrute": "TIMEOUT"})

            else:
                logger.error("[-] No or unidentified task specified! Task was: {}".format(one_task))
                return False

        # Need to check if the current Nessus scan is complete
        if fresh_nessus is not None and self.resultsdict["nessus"] != "NA":
            if nessus_task.checkScanStatus(fresh_nessus) == "COMPLETE":
                nessus_task.downloadReport(fresh_nessus)
            else:
                logger.warning(
                    "[!] Tenable scan for target is still underway, check the TIO console manually for results."
                )

        return self.resultsdict
