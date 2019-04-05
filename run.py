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


def parseCmdArgs():

    parser = argparse.ArgumentParser(usage='run.py [options] target', 
                                     description="Sequentially run a number of\
                                     tasks to perform a vulnerability assessment on a target.")
    # Note: These two are not implemented yet
    argument_group = parser.add_mutually_exclusive_group()
    argument_group.add_argument('-v', '--verbose', 
                                action='store_true', 
                                help="increase tool verbosity",
                                default=False)
    argument_group.add_argument('-q', '--quiet',
                                action='store_true',
                                help="quiet run, show almost no output",
                                default=False)
    
    # target is a positional argument, must be specified
    parser.add_argument('target',
                        help="host to scan - this could be an IP address, FQDN or a hostname")
    parser.add_argument('-a',
                        dest='all',
                        action='store_true',
                        help="Run ALL tasks on the target",
                        default=False)                  
    parser.add_argument('-p',
                        dest='port_scan',
                        action='store_true',
                        help="Run a port scan (nmap) on the target",
                        default=False)             
    parser.add_argument('-o',
                        dest='httpobs_scan',
                        action='store_true',
                        help="Run HTTP Observatory scan on the target",
                        default=False)
    parser.add_argument('-t',
                        dest='tlsobs_scan',
                        action='store_true',
                        help="Run TLS Observatory scan on the target",
                        default=False)
    parser.add_argument('-s',
                        dest='ssh_scan',
                        action='store_true',
                        help="Run ssh_scan on the target",
                        default=False)
    parser.add_argument('-d',
                        dest='direnum_scan',
                        action='store_true',
                        help="Run directory enumeration scan on the target",
                        default=False)
    parser.add_argument('-n',
                        dest='nessus_scan',
                        action='store_true',
                        help="Run Tenable.io (Nessus) scan on the target",
                        default=False)

    args = parser.parse_args()
    return args


def setupVA(va_target, arguments):

    if arguments.all:
        # No smart logic, just add & run all tasks
        va_target.addTask(task.NessusTask(va_target))
        va_target.addTask(task.NmapTask(va_target))
        va_target.addTask(task.SSHScanTask(va_target))
        va_target.addTask(task.MozillaHTTPObservatoryTask(va_target))
        va_target.addTask(task.MozillaTLSObservatoryTask(va_target))
        va_target.addTask(task.DirectoryBruteTask(va_target, tool="dirb"))

        return va_target

    # Regardless of the type of target, we will run:
    # 1. Nessus scan
    # 2. Nmap scan
    # Also kicking of Nessus scan as the first task as it takes time
    # Note: Passed flags can override these
    if arguments.port_scan:
        va_target.addTask(task.NmapTask(va_target))
        va_target.resultsdict.update({'nmap': False})
    if arguments.nessus_scan:
        va_target.addTask(task.NessusTask(va_target))
        va_target.resultsdict.update({'nessus': False})
    if arguments.ssh_scan:
        va_target.addTask(task.SSHScanTask(va_target))
        va_target.resultsdict.update({'sshscan': False})
    
    if "URL" in va_target.getType():
        # We have a URL, means HTTP Obs, TLS Obs,
        # and directory brute scans are a go
        # Note: Passed flags can override these
        if va_target.getType() == "FQDN|URL":
            # We can run all tools/tasks
            if arguments.httpobs_scan:
                va_target.addTask(task.MozillaHTTPObservatoryTask(va_target))
                va_target.resultsdict.update({'httpobs': False})
            if arguments.tlsobs_scan:
                va_target.addTask(task.MozillaTLSObservatoryTask(va_target))
                va_target.resultsdict.update({'tlsobs': False})
            if arguments.direnum_scan:
                va_target.addTask(task.DirectoryBruteTask(va_target, tool="dirb"))
                va_target.resultsdict.update({'dirbrute': False})
        else:
            if arguments.tlsobs_scan:
                va_target.addTask(task.MozillaTLSObservatoryTask(va_target))
                va_target.resultsdict.update({'tlsobs': False})
            if arguments.direnum_scan:
                va_target.addTask(task.DirectoryBruteTask(va_target, tool="dirb"))
                va_target.resultsdict.update({'dirbrute': False})
            # HTTP Observatory does not like IPs as a target, skipping
            va_target.resultsdict.update({"httpobs": "PASS"})
            va_target.resultsdict.update({"websearch": "PASS"})
    elif va_target.getType() == "IPv4":
        if arguments.tlsobs_scan:
            va_target.addTask(task.MozillaTLSObservatoryTask(va_target))
            va_target.resultsdict.update({'tlsobs': False})
        if arguments.direnum_scan:
            va_target.addTask(task.DirectoryBruteTask(va_target, tool="dirb"))
            va_target.resultsdict.update({'dirbrute': False})
        # Again, HTTP Observatory does not like IPs as a target, skipping
    else:
        # FQDN, we can run all tools/tasks
        if arguments.httpobs_scan:
            va_target.addTask(task.MozillaHTTPObservatoryTask(va_target))
            va_target.resultsdict.update({'httpobs': False})
        if arguments.tlsobs_scan:
            va_target.addTask(task.MozillaTLSObservatoryTask(va_target))
            va_target.resultsdict.update({'tlsobs': False})
        if arguments.direnum_scan:
            va_target.addTask(task.DirectoryBruteTask(va_target, tool="dirb"))
            va_target.resultsdict.update({'dirbrute': False})
    
    return va_target


def showScanSummary(result_dictionary):

    coloredlogs.install(level="INFO", logger=logger, reconfigure=True, fmt="%(levelname)-10s %(message)s")

    print("\n====== SCAN SUMMARY ======")
    for one_task, status in result_dictionary.items():
        if status:
            if status == "NA":
                logger.warning("[!] [ :| ] " + one_task + " scan skipped as not specified.")
            elif status == "TIMEOUT":
                logger.warning("[!] [ :| ] " + one_task + " timed out and was killed! Run manually.")
            else:
                logger.info("[+] [\o/] " + one_task + " scan completed successfully!")
        else:
            logger.error("[-] [ :( ] " + one_task + " scan failed to run. Please investigate or run manually.")

    print("====== END OF SCAN =======\n")


def runVA(scan_with_tasks, outpath, compress_results):
    logger.info("[+] Running the scans now. This may take a while...")
    results = scan_with_tasks.runTasks()
    # results here is a dict
    time.sleep(1)
    # Return code check is a bit hacky,
    # basically we are ignoring warnings from tar

    if compress_results:
        if utils.package_results(outpath).returncode is not 127:
            logger.info("[+] All done. Tool output from the scan can be found at " + outpath)
        else:
            logger.warning("[!] There was a problem compressing tool output. Check " + outpath + " manually.")
    time.sleep(1)
    showScanSummary(results)


def main():
    
    scan_success = {
        'nmap': "NA",
        'nessus': "NA",
        'tlsobs': "NA",
        'httpobs': "NA", 
        'sshscan': "NA", 
        'dirbrute': "NA"
    }
    compress_results = True
    tool_arguments = parseCmdArgs()
    destination = tool_arguments.target
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
    
    va_scan = setupVA(va_target, tool_arguments)
    if not tool_arguments.all:
        compress_results = False
    runVA(va_scan, output_path, compress_results)


if __name__ == "__main__":
    main()
