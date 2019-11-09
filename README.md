# smbspider2
Rewrite of the original SMBSpider.py script. This takes care of some of the error output by first performing a port scan on the target/target list to see if the port is open.  If SMB is open, THEN it will perform recon on shares and subdirectories.

Another thing that this script does that the old script doesn't do is it automatically enumerates shares... So no more specifying specific shares and subfolders... Just point and shoot and let this do all the work.

Currently this script looks for *.ps1 *.kdb *.kdbx and and filenames containing the string password.

# Help Menu
```
# ./smbspider2.py --help
usage: smbspider2.py [-h] -ip IPADDRESS -u USER -p PWD -d DOMAIN [-t THREADS]

SMB Spider for Potentially Sensitve Files. I.E Powershell Scripts, KeePass
Databases, and files that contain "password" in the filename.

optional arguments:
  -h, --help            show this help message and exit
  -ip IPADDRESS, --ipaddress IPADDRESS
                        ip address
  -u USER, --user USER  user
  -p PWD, --pwd PWD     password
  -d DOMAIN, --domain DOMAIN
                        domain
  -t THREADS, --threads THREADS
                        number of threads
```
# Example Usage:
```
# ./smbspider2.py -ip 172.16.6.0/24 -u testuser1 -p Summer2019 -d tgore.com -t 100
[*] Scanning Port 445 on host 172.16.6.1
 [*] Scanning Port 445 on host 172.16.6.2
[*] Scanning Port 445 on host 172.16.6.3
[*] Scanning Port 445 on host 172.16.6.4
[*] Scanning Port 445 on host 172.16.6.5
[*] Scanning Port 445 on host 172.16.6.6
[*] Scanning Port 445 on host 172.16.6.7
[*] Scanning Port 445 on host 172.16.6.8
[*] Scanning Port 445 on host 172.16.6.9
 [*] Scanning Port 445 on host 172.16.6.10
[*] Scanning Port 445 on host 172.16.6.11
[*] Scanning Port 445 on host 172.16.6.12
[*] Scanning Port 445 on host 172.16.6.13
[*] Scanning Port 445 on host 172.16.6.14
[*] Scanning Port 445 on host 172.16.6.15
<<snip>>
```
This script can take single IP's, / notation, or a file of IPs and/or slash notated ranges.

Credit:
https://github.com/T-S-A/smbspider
