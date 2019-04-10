#!/usr/bin/python3

import sys
import os
import time
import logging
import coloredlogs
import argparse
from urllib.parse import urlparse
from lib import target, task, utils

# Logging in UTC
logger = logging.getLogger(__name__)
coloredlogs.install(
    level="INFO",
    logger=logger,
    reconfigure=True,
    fmt="[%(hostname)s] %(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %I:%M:%S %p %Z",
)


def setupVA(va_target):

    # Regardless of the type of target, we will run:
    # 1. Nessus scan
    # 2. Nmap scan
    # Also kicking of Nessus scan as the first task as it takes time
    va_target.addTask(task.NessusTask(va_target))
    va_target.addTask(task.NmapTask(va_target))
    
    if "URL" in va_target.getType():
        # We have a URL, means HTTP Obs, TLS Obs,
        # and directory brute scans are a go
        if va_target.getType() == "FQDN|URL":
            # We can run all tools/tasks
            va_target.addTask(task.MozillaHTTPObservatoryTask(va_target))
            va_target.addTask(task.MozillaTLSObservatoryTask(va_target))
            va_target.addTask(task.DirectoryBruteTask(va_target, tool="dirb"))
            va_target.addTask(task.WebSearchTask(va_target))
        else:
            va_target.addTask(task.MozillaTLSObservatoryTask(va_target))
            va_target.addTask(task.DirectoryBruteTask(va_target, tool="dirb"))
            # HTTP Observatory does not like IPs as a target, skipping
            va_target.resultsdict.update({"httpobs": "PASS"})
            # Also skipping web search for the IP address targets
            va_target.resultsdict.update({"websearch": "PASS"})
    elif va_target.getType() == "IPv4":
        va_target.addTask(task.MozillaTLSObservatoryTask(va_target))
        va_target.addTask(task.DirectoryBruteTask(va_target, tool="dirb"))
        # Again, HTTP Observatory does not like IPs as a target, skipping
        va_target.resultsdict.update({"httpobs": "PASS"})
        va_target.resultsdict.update({"websearch": "PASS"})
    else:
        # FQDN, we can run all tools/tasks
        va_target.addTask(task.MozillaHTTPObservatoryTask(va_target))
        va_target.addTask(task.MozillaTLSObservatoryTask(va_target))
        va_target.addTask(task.DirectoryBruteTask(va_target, tool="dirb"))
        va_target.addTask(task.WebSearchTask(va_target))
    
    return va_target


def showScanSummary(result_dictionary):

    coloredlogs.install(level="INFO", logger=logger, reconfigure=True, fmt="%(levelname)-10s %(message)s")

    print("\n====== SCAN SUMMARY ======")
    for one_task, status in result_dictionary.items():
        if status:
            if status == "PASS":
                logger.warning("[!] [ :| ] " + one_task + " scan skipped as not applicable to the target.")
            elif status == "TIMEOUT":
                logger.warning("[!] [ :| ] " + one_task + " timed out and was killed! Run manually if you like.")
            else:
                logger.info("[+] [\o/] " + one_task + " scan completed successfully!")
        else:
            logger.error("[-] [ :( ] " + one_task + " scan failed to run. Please investigate or run manually.")

    print("====== END OF SCAN =======\n")


def runVA(scan_with_tasks, outpath):
    logger.info("[+] Running all the scans now. This may take a while...")
    results = scan_with_tasks.runTasks()
    # results here is a dict
    time.sleep(1)
    # Return code check is a bit hacky,
    # basically we are ignoring warnings from tar

    if utils.package_results(outpath).returncode is not 127:
        logger.info("[+] All done. Tool output from the scan can be found at " + outpath)
    else:
        logger.warning("[!] There was a problem compressing tool output. Check " + outpath + " manually.")
    time.sleep(1)
    showScanSummary(results)


def main():
    
    scan_success = {
        'nmap': False,
        'nessus': False,
        'tlsobs': False,
        'httpobs': False,
        'sshscan': "PASS",  # Default is PASS, as it only gets updated to True as a part of nmap scan task
        'websearch': False,
        'dirbrute': False
    }
    destination = sys.argv[1]
    output_path = "/app/results/" + destination + "/"
    va_target = target.Target(destination, scan_success)

    if va_target.isValid():
        # We have a valid target, what is it?
        if "URL" in va_target.getType():
            domain = urlparse(va_target.targetname).netloc
            output_path = "/app/results/" + domain + "/"
    else:
        logger.error("[-] Invalid target, please use an FQDN or a URL.")
        sys.exit(-1)

    # Create a location to store our outputs
    try:
        os.stat(output_path)
    except Exception:
        os.mkdir(output_path)

    va_scan = setupVA(va_target)
    runVA(va_scan, output_path)
    

if __name__ == "__main__":
    main()
