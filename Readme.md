# vautomator-standalone
Iterative automation of common VA tasks using OOP.

If you'd like to contribute, please reach out to [me](https://mozillians.org/en-US/u/Cag/) and I'd be happy to add you as a contributor.

## Install & Running 

1. First, download the repo: `git clone https://github.com/caggle/vautomator-standalone.git && cd vautomator-standalone`
2. Build the Docker image: `docker-compose build vautomator`
3. Run it!: `docker run -v ${PWD}/results:/app/results -it vautomator:latest ./run.py <target>`

Example run:
```
$ docker run -v ${PWD}/results:/app/results -it vautomator:latest ./run.py http://192.168.0.1
[f2769b83b62b] 2019-01-21 06:23:51 AM UTC INFO     [+] Running all the scans now. This may take a while...
[f2769b83b62b] 2019-01-21 06:24:23 AM UTC WARNING  [!] The target has recently been scanned by Tenable.io, retrieving results...
[f2769b83b62b] 2019-01-21 06:24:30 AM UTC INFO     [+] Running nmap port scans...
[f2769b83b62b] 2019-01-21 06:26:54 AM UTC INFO     [+] Nmap port scan(s) successfully ran.
[f2769b83b62b] 2019-01-21 06:26:54 AM UTC INFO     [+] Running ssh_scan...
[f2769b83b62b] 2019-01-21 06:26:58 AM UTC INFO     [+] SSH scan successfully ran.
[f2769b83b62b] 2019-01-21 06:26:58 AM UTC INFO     [+] Running TLS Observatory scan...
[f2769b83b62b] 2019-01-21 06:27:19 AM UTC INFO     [+] TLS Observatory scan successfully ran.
[f2769b83b62b] 2019-01-21 06:27:19 AM UTC INFO     [+] Running dirb scan...
[f2769b83b62b] 2019-01-21 06:31:48 AM UTC INFO     [+] Directory brute scan successfully ran.
[f2769b83b62b] 2019-01-21 06:31:49 AM UTC INFO     [+] All done. Tool output from the scan can be found at /app/results/192.168.0.1/

====== SCAN SUMMARY ======
INFO       [+] [\o/] nmap scan completed successfully!
INFO       [+] [\o/] dirbrute scan completed successfully!
INFO       [+] [\o/] sshscan scan completed successfully!
INFO       [+] [\o/] tlsobs scan completed successfully!
INFO       [+] [\o/] nessus scan completed successfully!
WARNING    [!] [ :| ] httpobs scan skipped as not applicable to the target.
====== END OF SCAN =======
```

## What it does

Using **Python 3**, it runs a bunch of tools against a URL/FQDN/IPv4 address on a Docker image of its own, and saves tool outputs for later analysis, as a part of a vulnerability assessment.

### What it actually does

* Determines if the the target is a URL, an IPv4 address or a hostname/FQDN
* If URL *(note: it could be a URL with FQDN or IPv4 address)* it will run:
  * An nmap UDP scan for about 25 selected UDP services
  * An nmap TCP scan for top 1000 services
  * ssh_scan (if an SSH service is identified)
  * A Nessus (Tenable.io) "Basic Network Scan" (provided if you have valid Tenable.io API keys)
  * HTTP Observatory scan
  * TLS Observatory scan
  * Directory bruteforcing against a wordlist
  
* If IP address, it will only run:
  * An nmap UDP scan for about 25 selected UDP services
  * An nmap TCP scan for top 1000 services
  * ssh_scan (if an SSH service is identified)
  * A Nessus (Tenable.io) "Basic Network Scan" (provided if you have valid Tenable.io API keys)
  
In the current implementation these tasks are performed sequentially with the intent being "run and forget" for a couple of hours, while you are doing other important work.

#### Port scans

For TCP and UDP port scans, [python-nmap](https://pypi.org/project/python-nmap/) is used.

##### SSH scan

For SSH scan, [ssh_scan](https://github.com/mozilla/ssh_scan) is used.

#### Nessus scan

Nessus scans will fail unless you have a pair of valid Tenable.io API keys *with administrative permissions*. If you do, populate the .env file with them in the below form building the Docker image:

```
TENABLEIO_ACCESS_KEY=<ACCESS_KEY>
TENABLEIO_SECRET_KEY=<SECRET_KEY>
```

#### Web App scans

If you are running the tool against a URL, a number of additional external tools will be utilised. These will be installed in the Docker container when you build it.
* [HTTP Observatory](https://github.com/mozilla/http-observatory) is used as a Python module.
* [TLS Observatory](https://github.com/mozilla/tls-observatory), by means of `tlsobs` client.
* For directory brute-forcing:
  * By default, `dirb` will be used with the common wordlist.
  * `gobuster` will also be installed in the Docker container, however a command line switch to use it instead is not available yet (you would have to modify the code).
