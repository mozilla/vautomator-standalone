import os
import logging
import coloredlogs
import json
import nmap
import subprocess
import time
from lib import utils
from tenable_io.client import TenableIOClient
from tenable_io.exceptions import TenableIOApiException
from tenable_io.api.scans import ScanExportRequest
from tenable_io.api.models import Scan
from distutils.spawn import find_executable

# Logging in UTC
logger = logging.getLogger(__name__)
coloredlogs.install(
    level="INFO",
    logger=logger,
    reconfigure=True,
    fmt="[%(hostname)s] %(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %I:%M:%S %p %Z",
)


class Task:
    # One target will have at least one task
    # One task will have one target at a time
    # self.tasktarget here is a Target object
    def __init__(self, target_obj):
        self.tasktarget = target_obj

    def wait_process_timeout(self, proc, seconds):
        """Wait for a process to finish, or raise exception after timeout"""
        start = time.time()
        end = start + seconds
        interval = min(seconds / 1000.0, 0.25)

        while True:
            result = proc.poll()
            if result is not None:
                return result
            if time.time() >= end:
                raise RuntimeError("Process timed out")
            time.sleep(interval)


class NmapTask(Task):
    def __init__(self, target_obj, scan_type="full"):
        super().__init__(target_obj)
        self.portscan_type = scan_type

    def checkForSSH(self, port_scan_results):
        # We need to check if SSH service is available within port scan results
        if port_scan_results["".join(port_scan_results.all_hosts())].has_tcp(22):
            # Port 22/tcp is open, perform ssh_scan scan
            self.tasktarget.addTask(SSHScanTask(self.tasktarget, 22))

        else:
            # Need to find the actual SSH port, in case it is not 22
            # Magic happens here...
            # Ref: https://bitbucket.org/xael/python-nmap/src/2b493f71a26f63a01c155c073fbf0211a3219ff2/
            # nmap/nmap.py?at=default&fileviewer=file-view-default#nmap.py-436:465
            for ssh_port in port_scan_results["".join(port_scan_results.all_hosts())].all_tcp():
                if "script" in port_scan_results["".join(port_scan_results.all_hosts())]["tcp"][ssh_port].keys():
                    if (
                        "ssh"
                        in "".join(
                            port_scan_results["".join(port_scan_results.all_hosts())]["tcp"][ssh_port][
                                "script"
                            ].values()
                        ).lower()
                    ):
                        # We have SSH service on a non-standard port, perform scan
                        self.tasktarget.addTask(SSHScanTask(self.tasktarget, ssh_port))
        return

    def runNmapScan(self):

        # Note, python-nmap relies on nmap being installed
        # Need to ensure nmap is installed via Dockerfile
        # We are NOT using subprocess calls here

        logger.info("[+] Running nmap port scans...")

        nm = nmap.PortScanner()
        isSudo = False
        udp_ports = (
            "17,19,53,67,68,123,137,138,139,"
            "161,162,500,520,646,1900,3784,3785,5353,27015,"
            "27016,27017,27018,27019,27020,27960"
        )
        if self.portscan_type == "tcp":
            nmap_arguments = "-v -Pn -sT -sV --script=banner --top-ports 1000 --open -T4 --system-dns"
            results = nm.scan(self.tasktarget.targetdomain, arguments=nmap_arguments, sudo=isSudo)

        elif self.portscan_type == "udp":
            nmap_arguments = "-v -Pn -sU -sV --open -T4 --system-dns"
            results = nm.scan(self.tasktarget.targetdomain, ports=udp_ports, arguments=nmap_arguments, sudo=isSudo)

        else:
            # Need to run both UDP and TCP scans
            # This looks rather ugly however it's a current way to
            # specify different ports for TCP and UDP scans in a
            # single nmap command: https://seclists.org/nmap-dev/2011/q2/365
            # TODO: Perhaps read this from an environment variable or config
            tcp_top1000_ports = (
                "1,3-4,6-7,9,13,17,19-26,30,32-33,"
                "37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,"
                "113,119,125,135,139,143-144,146,161,163,179,199,"
                "211-212,222,254-256,259,264,280,301,306,311,340,"
                "366,389,406-407,416-417,425,427,443-445,458,464-465,"
                "481,497,500,512-515,524,541,543-545,548,554-555,563,"
                "587,593,616-617,625,631,636,646,648,666-668,683,687,"
                "691,700,705,711,714,720,722,726,749,765,777,783,787,"
                "800-801,808,843,873,880,888,898,900-903,911-912,981,"
                "987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,"
                "1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,"
                "1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,"
                "1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,"
                "1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,"
                "1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,"
                "1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,"
                "1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,"
                "1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,"
                "1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,"
                "1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,"
                "2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,"
                "2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,"
                "2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,"
                "2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,"
                "2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,"
                "2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,"
                "2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,"
                "3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,"
                "3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,"
                "3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,"
                "3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,"
                "3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,"
                "3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,"
                "4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,"
                "4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,"
                "5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,"
                "5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,"
                "5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,"
                "5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,"
                "5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,"
                "5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,"
                "5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,"
                "6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,"
                "6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,"
                "6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,"
                "7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,"
                "7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,"
                "8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,"
                "8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,"
                "8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,"
                "8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,"
                "9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,"
                "9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,"
                "9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,"
                "9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,"
                "10243,10566,10616-10617,10621,10626,10628-10629,10778,"
                "11110-11111,11967,12000,12174,12265,12345,13456,13722,"
                "13782-13783,14000,14238,14441-14442,15000,15002-15004,"
                "15660,15742,16000-16001,16012,16016,16018,16080,16113,"
                "16992-16993,17877,17988,18040,18101,18988,19101,19283,"
                "19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,"
                "20828,21571,22939,23502,24444,24800,25734-25735,26214,"
                "27000,27352-27353,27355-27356,27715,28201,30000,30718,"
                "30951,31038,31337,32768-32785,33354,33899,34571-34573,"
                "35500,38292,40193,40911,41511,42510,44176,44442-44443,"
                "44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,"
                "49400,49999-50003,50006,50300,50389,50500,50636,50800,"
                "51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,"
                "55555,55600,56737-56738,57294,57797,58080,60020,60443,"
                "61532,61900,62078,63331,64623,64680,65000,65129,65389"
            )
            nmap_arguments = (
                "-v -Pn -sTU -sV --script=banner -p T:"
                + tcp_top1000_ports
                + ",U:"
                + udp_ports
                + " --open -T4 --system-dns"
            )
            results = nm.scan(self.tasktarget.targetdomain, arguments=nmap_arguments, sudo=isSudo)

        self.checkForSSH(nm)

        if results:
            try:
                nmap_output = open("/app/results/" + self.tasktarget.targetdomain + "/" + "nmap.json", "w+")
                nmap_output.write(json.dumps(results))
                return True
            except Exception:
                logger.error("[-] Could not open file for nmap output!")
                return False


class SSHScanTask(Task):
    def __init__(self, target_obj, sshport=22):
        super().__init__(target_obj)
        self.ssh_port = sshport

    def runSSHScan(self):
        if find_executable("ssh_scan"):
            # Found in path, run the command
            logger.info("[+] Running ssh_scan...")
            cmd = (
                "ssh_scan -t "
                + self.tasktarget.targetdomain
                + " -p "
                + str(self.ssh_port)
                + " -o /app/results/"
                + self.tasktarget.targetdomain
                + "/ssh_scan.txt"
            )
            sshscan_cmd = utils.sanitise_shell_command(cmd)
            p = subprocess.Popen(sshscan_cmd, stdout=subprocess.PIPE, shell=True)
            p.wait()
            return p
        else:
            logger.error("[-] ssh_scan not found in Docker image!")
            return False


class NessusTask(Task):
    def __init__(self, target_obj):
        super().__init__(target_obj)
        # According to documentation TenableIO client can be initialised
        # in a number of ways. I choose here the environment variable option.
        self.tio_access_key = os.getenv("TENABLEIO_ACCESS_KEY")
        self.tio_secret_key = os.getenv("TENABLEIO_SECRET_KEY")

    def runNessusScan(self):

        # First, check to see if we are provided with API keys
        if self.tio_access_key == "" or self.tio_secret_key == "":
            logger.warning(
                "[!] Tenable.io API key(s) not provided, skipping " "Tenable.io scan. Perform the scan manually."
            )
            return False
        else:
            self.client = TenableIOClient(access_key=self.tio_access_key, secret_key=self.tio_secret_key)

        # Reference: https://github.com/tenable/Tenable.io-SDK-for-Python/blob/master/examples/scans.py
        # Note no subprocess call is required here
        try:
            # Run a basic network scan on the target
            # Need to check if a recent scan was fired recently
            scan_name = "VA for " + self.tasktarget.targetdomain
            # We will check with both host IP and FQDN
            activities = self.client.scan_helper.activities(targets=self.tasktarget.targetdomain, date_range=15)
            if len(activities) > 0:
                logger.warning("[!] The target has recently been scanned by Tenable.io, retrieving results...")
                old_nscans = self.client.scan_helper.scans(name=scan_name)
                for old in old_nscans:
                    if old.status() == Scan.STATUS_COMPLETED:
                        self.downloadReport(old)
                        break
                return old
            else:
                # This target was not scanned before, scan it
                # We don't want this blocking, so don't wait
                new_nscan = self.client.scan_helper.create(
                    name=scan_name, text_targets=self.tasktarget.targetdomain, template="basic"
                )
                new_nscan.launch(wait=False)
                return new_nscan

        except TenableIOApiException as TIOException:
            logger.error("[-] Tenable.io scan failed: ".format(TIOException))
            return False

    def downloadReport(self, nscan, reportformat="html", style="assets"):
        report_path = "/app/results/" + self.tasktarget.targetdomain + "/Scan_for_" + self.tasktarget.targetdomain

        if reportformat == "html":
            fmt = ScanExportRequest.FORMAT_HTML
        elif reportformat == "pdf":
            fmt = ScanExportRequest.FORMAT_PDF
        elif reportformat == "csv":
            fmt = ScanExportRequest.FORMAT_CSV
        elif reportformat == "nessus":
            fmt = ScanExportRequest.FORMAT_NESSUS
        elif reportformat == "db":
            fmt = ScanExportRequest.FORMAT_DB
        else:
            return False

        if style == "assets":
            reportoutline = ScanExportRequest.CHAPTER_CUSTOM_VULN_BY_HOST
        elif style == "exec":
            reportoutline = ScanExportRequest.CHAPTER_EXECUTIVE_SUMMARY
        elif style == "plugins":
            reportoutline = ScanExportRequest.CHAPTER_CUSTOM_VULN_BY_PLUGIN
        else:
            return False

        nscan.download(report_path, format=fmt, chapter=reportoutline)

    def checkScanStatus(self, nscan):
        # Query Tenable API to check if the scan is finished
        status = nscan.status()

        if status == Scan.STATUS_COMPLETED:
            return "COMPLETE"
        elif status == Scan.STATUS_ABORTED:
            return "ABORTED"
        elif status == Scan.STATUS_INITIALIZING:
            return "INITIALIZING"
        elif status == Scan.STATUS_PENDING:
            return "PENDING"
        elif status == Scan.STATUS_RUNNING:
            return "RUNNING"
        else:
            logger.error("[-] Something is wrong with Tenable.io scan. Check the TIO console manually.")
            return False


class MozillaHTTPObservatoryTask(Task):
    def __init__(self, target_obj):
        super().__init__(target_obj)

    def runHttpObsScan(self):
        if "IPv4" in self.tasktarget.type:
            # HTTP Obs only accepts FQDN
            return False

        if find_executable("observatory"):
            # Found in path, run the command
            logger.info("[+] Running HTTP Observatory scan...")
            cmd = (
                "observatory --format=report -z --rescan "
                + self.tasktarget.targetdomain
                + " > /app/results/"
                + self.tasktarget.targetdomain
                + "/httpobs_scan.txt"
            )
            observatory_cmd = utils.sanitise_shell_command(cmd)
            p = subprocess.Popen(observatory_cmd, stdout=subprocess.PIPE, shell=True)
            p.wait()
            return p

        else:
            logger.error("[-] HTTP Observatory not found in Docker image!")
            return False


class MozillaTLSObservatoryTask(Task):
    def __init__(self, target_obj):
        super().__init__(target_obj)

    def runTLSObsScan(self):
        if find_executable("tlsobs"):
            # Found in path, run the command
            logger.info("[+] Running TLS Observatory scan...")
            cmd = (
                "tlsobs -r -raw "
                + self.tasktarget.targetname
                + " > /app/results/"
                + self.tasktarget.targetdomain
                + "/tlsobs_scan.txt"
            )
            tlsobs_cmd = utils.sanitise_shell_command(cmd)
            p = subprocess.Popen(tlsobs_cmd, stdout=subprocess.PIPE, shell=True)
            p.wait()
            return p
        else:
            logger.error("[-] TLS Observatory not found in Docker image!")
            return False


class DirectoryBruteTask(Task):
    def __init__(self, target_obj, tool="dirb"):
        super().__init__(target_obj)
        self.toolToRun = tool

    def runDirectoryBruteScan(self):
        if self.toolToRun == "dirb":
            # dirb is compiled from source, won't be in the PATH
            # Also defaulting to HTTPS URL here
            logger.info("[+] Running dirb scan...")
            if "URL" in self.tasktarget.getType():
                cmd = (
                    "/app/vendor/dirb222/dirb "
                    + self.tasktarget.targetname
                    + "/ /app/vendor/dirb222/wordlists/common.txt -o /app/results/"
                    + self.tasktarget.targetdomain
                    + "/https_dirb_common.txt -f -w -S -r"
                )
            else:
                cmd = (
                    "/app/vendor/dirb222/dirb https://"
                    + self.tasktarget.targetdomain
                    + "/ /app/vendor/dirb222/wordlists/common.txt -o /app/results/"
                    + self.tasktarget.targetdomain
                    + "/https_dirb_common.txt -f -w -S -r"
                )

            dirbscan_cmd = utils.sanitise_shell_command(cmd)
            p = subprocess.Popen(dirbscan_cmd, stdout=subprocess.PIPE, shell=True)
            try:
                # Give it 15min
                self.wait_process_timeout(p, 900)
            except RuntimeError:
                p.kill()
                logger.warning("[!] dirb timed out, process killed")

            return p
        elif self.toolToRun == "gobuster":
            logger.info("[+] Running gobuster scan...")
            if "URL" in self.tasktarget.getType():
                cmd = (
                    "go run /app/vendor/gobuster-master/main.go "
                    + self.tasktarget.targetname
                    + " -w /app/vendor/dirb222/wordlists/common.txt -v -l -o /app/results/"
                    + self.tasktarget.targetdomain
                    + "/gobuster_common.txt"
                )
            else:
                cmd = (
                    "go run /app/vendor/gobuster-master/main.go https://"
                    + self.tasktarget.targetdomain
                    + " -w /app/vendor/dirb222/wordlists/common.txt -v -l -o /app/results/"
                    + self.tasktarget.targetdomain
                    + "/gobuster_common.txt"
                )

            gobuster_cmd = utils.sanitise_shell_command(cmd)
            p = subprocess.Popen(gobuster_cmd, stdout=subprocess.PIPE, shell=True)
            p.wait()
            return p
