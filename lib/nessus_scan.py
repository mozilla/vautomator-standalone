import os
import logging
import coloredlogs
from lib import task
from tenable_io.client import TenableIOClient
from tenable_io.exceptions import TenableIOApiException
from tenable_io.api.scans import ScanExportRequest
from tenable_io.api.models import Scan

# This looks ugly and unnecessary in all files, 
# should implement per module logging
logger = logging.getLogger(__name__)
coloredlogs.install(level='INFO', logger=logger, reconfigure=True,
                    fmt='[%(hostname)s] %(asctime)s %(levelname)-8s %(message)s',
                    datefmt="%Y-%m-%d %I:%M:%S %p %Z")


class NessusTask(task):

    def __init__(self, target_obj):
        super().__init__(target_obj)
        # According to documentation TenableIO client can be initialised
        # in a number of ways. I choose here the environment variable option.
        self.tio_access_key = os.getenv('TENABLEIO_ACCESS_KEY')
        self.tio_secret_key = os.getenv('TENABLEIO_SECRET_KEY')

    def runNessusScan(self):

        # First, check to see if we are provided with API keys
        if (self.tio_access_key == "" or self.tio_secret_key == ""):
            logger.warning("[!] Tenable.io API key(s) not provided, skipping "
                           "Tenable.io scan. Perform the scan manually.")
            return False
        else:
            self.client = TenableIOClient(access_key=self.tio_access_key, secret_key=self.tio_secret_key)

        # Reference: https://github.com/tenable/Tenable.io-SDK-for-Python/blob/master/examples/scans.py
        # Note no subprocess call is required here
        try:
            # Run a basic network scan on the target
            # Need to check if a recent scan was fired recently
            scan_name = "VA for " + self.tasktarget.targetdomain
            activities = self.client.scan_helper.activities(targets=self.tasktarget.targetdomain, date_range=15)
            if (len(activities) > 0):
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
                new_nscan = self.client.scan_helper.create(name=scan_name, text_targets=self.tasktarget.targetdomain, template='basic')
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
        status = nscan.status(nscan.id)

        if status == nscan.STATUS_COMPLETED:
            return "COMPLETE"
        elif status == nscan.STATUS_ABORTED:
            return "ABORTED"
        elif status == nscan.STATUS_INITIALIZING:
            return "INITIALIZING"
        elif status == nscan.STATUS_PENDING:
            return "PENDING"
        elif status == nscan.STATUS_RUNNING:
            return "RUNNING"
        else:
            logger.error("[-] Something is wrong with Tenable.io scan. Check the TIO console manually.")
            return False
