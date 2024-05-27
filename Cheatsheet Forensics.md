# 2024 Forensics Cheatsheet

## Table of Contents

**1. [General](#1-general)**

**2. [Disk forensics](#2-disk-forensics)**

* [Metadata](#metadata)
* [Disk backup](#disk-backup)
* [File system analysis](#file-system-analysis)

**3. [Operating system forensics (Linux)](#3-operating-system-forensics)**

*[Live forensics](#live-forensics)
*[Post- mortem forensics](#post-mortem-forensics)

**4. [Operating system forensics (Windows)](#4-operating-system-forensics-windows)**

*[Live forensics](#live-forensics-1)
*[Post- mortem forensics](#post-mortem-forensics-1)

**5. [Memory forensics](#5-memory-forensics)**

## 1. General

[Eric Zimmermann Tools](https://ericzimmerman.github.io/#!index.md)

[VirusTotal](https://www.virustotal.com/gui/home/upload)

## 2. Disk forensics

### Metadata:

MAC-Time: 

`ls -l`

`stat`

Mounting:

`xmount --in <source format> <source location> --out <target format> <target location>`

### Disk Backup:

Tools:

`dd` `dcfldd` `dc3dd`

Sicherung: `dd if=/dev/<source> of=<dest>.img bs=65536 conv=noerror,sync`

Remote Sicherung über netcat: `dd if=/dev/<disk0> | nc <ip> <port>`

Hashwert: `sha256sum /dev/sdb`

Vergleich von Hashes:

    1. Masterkopie erzeugen & Hashwert vergleichen: `dd if=/dev/sdb of=masterkopie bs=512`
    `sha256sum masterkopie`

    2. Arbeitskopie von Masterkopie erzeugen & Hashwert vergleichen:
    `dd if=masterkopie of=arbeitskopie bs=512`
    `sha256sum arbeitskopie`

Piecewise Hashing (Tools):

    sdhash (binär)
    sdtext (text)

Context  Triggered Piecewise Hashing (Tools):

    ssdeep

### File system analysis:

#### Tools:

The Sleuth Kit (TSK):

autopsy



## 3. Operating system forensics (Linux)

### Live forensics:

### Post-mortem forensics:

## 4. Operating system forensics (Windows)

### Live forensics:

#### Tools:
`robocopy`

`doskey /history`

`tasklist /svc`

`listdlls`

![Windows or. external tools](images\Tools.png)
[Windows Sysinternals](https://docs.microsoft.com/de-de/sysinternals/downloads/sysinternals-suite)

https://live.sysinternals.com/

Ressource Monitor

[PowerForensics - PowerShell Digital Forensics](https://powerforensics.readthedocs.io/en/latest/)

#### Skripte:
[Invoke-LiveRespones](https://mgreen27.github.io/posts/2018/01/14/Invoke-LiveResponse.html)
[Live-Forensicator](https://github.com/Johnng007/Live-Forensicator)
[Huntress](https://github.com/zaneGittins/Huntress)

### Post-mortem forensics:

#### Locations:

Registry:

| Registry hive | description | Path to hive-file | environment variable | Supporting file
| ----------- | ----------- | ----------- | ----------- | ----------- | 
| HKEY_LOCAL_MACHINE\SAM | | C:\Windows\system32\ <br>config\SAM |  | Sam, Sam.log, Sam.sav | 
| HKEY_LOCAL_MACHINE\SECURITY | | C:\Windows\system32\ <br>config\SECURITY| | Security, Security.log, Security.sav | 
| HKEY_LOCAL_MACHINE\SOFTWARE | | C:\Windows\system32\ <br>config\SOFTWARE| | Software, Software.log, Software.sav | 
| HKEY_LOCAL_MACHINE\SYSTEM |  | C:\Windows\system32\ <br>config\SYSTEM| | System, System.alt, System.log, System.sav | 
| HKEY_CURRENT_CONFIG |  || | System, System.alt, System.log, System.sav, Ntuser.dat, Ntuser.dat.log| 
| HKEY_USERS\DEFAULT | | C:\Windows\system32\ <br>config\default | | Default, Default.log Default.sav |
| | system-/computer-wide configuration | | %SystemRoot%\ <br>System32\config | |
| | user-specific configuration | | %USERPROFILE%\ <br>NTUSER.dat | |
| HKEY_USERS |  |  C:\Documents and Setting\ <br>User Profile\NTUSER.DAT| | | 
| HKEY_LOCAL_MACHINE\Software\ <br>Microsoft\Windows\CurrentVersion\Run | Autorun from programms | | | | 
| HKEY_LOCAL_MACHINE\Software\ <br>Microsoft\Windows\CurrentVersion\RunOnce | Autorun from programms | | | | 
| HKEY_LOCAL_MACHINE\System\ <br>ControlSet00x\Enum\USBSTOR | connected USB-devices | | | | 
| HKEY_LOCAL_MACHINE\SOFTWARE\ <br>Microsoft\Windows NT\CurrentVersion\ <br>NetworkList\Profiles | connected WLAN | | | | 
| HKEY_CURRENT_USER\Software\ <br>Microsoft\Windows\CurrentVersion\ <br>Explorer\RecentDocs | currently opened documents | | | |
| HKEY_CURRENT_USER\software\ <br>microsoft\windows\currentversion\ <br>Explorer\RunMRU | userlist | | | |
| HKEY_CURRENT_USER\Software\ <br>Microsoft\Windows\Current Version\ <br>Explorer| MRU (Most Recently Used) | | | |
| | Shell Bags | C:\Users\BENUTZER\AppData\ <br>Local\Microsoft\ <br>Windows\USRCLASS.dat | | |
| HKCU\Software\Microsoft\ <br>Windows\CurrentVersion\ <br>Explorer\UserAssist | User Assist | | | |
| | Amcache.hve / RecentFileCache.bcf | | \%SystemRoot%\ <br>AppCompat\Programs\ <br>Amcache.hve | |
| SYSTEM\CurrentControlSet\ <br>Control\SessionManager\ <br>AppCompatCache | Registry: Shimcache (until Win10) <br>Path: Win11 Programm Compatibility Assistant (PCA) | | C:\Windows\ <br>appcompat\pca | |
| | Windows 10 Timeline |  C:\Users\<Benutzer>\ <br>AppData\Local\Connected <br>DevicesPlatform\L.<Benutzer>\ <br>ActivitiesCache.db | | |

#### Tools:

RegRipper(sometimes wrong outputs -> not used in entreprises commonly):

```
rip.pl -r <HIVE> -p <plugin>
```
[Plugin - HIVE Pair database](https://hexacorn.com/tools/3r.html)

[Plugin Database](https://github.com/keydet89/RegRipper3.0)

regtime plugin to create timeline etc.

```
reg.exe QUERY "HIVE-PATH" /s
example(getting VNC password): reg.exee QUERY "HKEY_LOCAL_MACHINE\Software\ORL\WinVNC3" \s
```
[Registry Explorer by Eric Zimmermann](https://www.sans.org/tools/registry-explorer/)

[Windows Registry Recovery - Donwload(Download starting)](https://www.mitec.cz/Downloads/WRR.zip)


### Supertimeline

[Plaso](https://plaso.readthedocs.io/en/latest/)

[Log2timeline - Timeline Color Template](https://github.com/riodw/Log2timeline-TIMELINE_COLOR_TEMPLATE)

### Incident Response Platforms (open source?)

CYBER TRIAGE

Velociraptor

GRR Rapid Response

## 5. Memory forensics


