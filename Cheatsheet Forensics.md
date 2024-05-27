# 2024 Forensics Cheatsheet

## Table of Contents

**1. [General](#1-general)**

**2. [Disk forensics](#2-disk-forensics)**

* [Metadata](#metadata)
* [Disk backup](#disk-backup)
* [File system analysis](#file-system-analysis)

**3. [Operating system forensics](#3-operating-system-forensics)**

* [Linux](#linux)
* [Windows](#windows)

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



## 3. Operating system forensics

### Linux

### Windows

#### Live forensics:

#### Tools:
[Windows Sysinternals](https://docs.microsoft.com/de-de/sysinternals/downloads/sysinternals-suite)

#### Skripte:



#### Post-mortem forensics:

#### Locations:

Registry:

| Registry hive | description | Path to hive-file | environment variable | Supporting file
| ----------- | ----------- | ----------- | ----------- | ----------- | 
| HKEY_LOCAL_MACHINE\SAM | | C:\Windows\system32\config\SAM |  | Sam, Sam.log, Sam.sav | 
| HKEY_LOCAL_MACHINE\SECURITY | | C:\Windows\system32\config\SECURITY| | Security, Security.log, Security.sav | 
| HKEY_LOCAL_MACHINE\SOFTWARE |  | C:\Windows\system32\config\SOFTWARE| | Software, Software.log, Software.sav | 
| HKEY_LOCAL_MACHINE\SYSTEM |  | C:\Windows\system32\config\SYSTEM| | System, System.alt, System.log, System.sav | 
| HKEY_CURRENT_CONFIG |  || | System, System.alt, System.log, System.sav, Ntuser.dat, Ntuser.dat.log| 
| HKEY_USERS\DEFAULT | | C:\Windows\system32\config\default | | Default, Default.log Default.sav |
| | System-/Computer-wide Configuration | | %SystemRoot%\System32\config | |
| | User-specific Configuration | | %USERPROFILE%\NTUSER.dat | |
| HKEY_USERS |  |  C:\Documents and Setting\User Profile\NTUSER.DAT| | | 
| HKEY_LOCAL_MACHINE\Software\ <br>Microsoft\Windows\CurrentVersion\Run | Autorun from programms | | | | 
| HKEY_LOCAL_MACHINE\Software\ <br>Microsoft\Windows\CurrentVersion\RunOnce | Autorun from programms | | | | 
| HKEY_LOCAL_MACHINE\System\ <br>ControlSet00x\Enum\USBSTOR | connected USB-devices | | | | 
| HKEY_LOCAL_MACHINE\SOFTWARE\ <br>Microsoft\Windows NT\CurrentVersion\ <br>NetworkList\Profiles | connected WLAN | | | | 
| HKEY_CURRENT_USER\Software\ <br>Microsoft\Windows\CurrentVersion\ <br>Explorer\RecentDocs | currently opened documents | | | |
| HKEY_CURRENT_USER\software\ <br>microsoft\windows\currentversion\ <br>Explorer\RunMRU | userlist | | | |



#### Tools:

RegRipper(sometimes wrong outputs -> not used in entreprises commonly):

```
rip.pl -r <HIVE> -p <plugin>
```
[Plugin - HIVE Pair database](https://hexacorn.com/tools/3r.html)

[Plugin Database](https://github.com/keydet89/RegRipper3.0)

regtime plugin to create timeline etc.

reg.exe QUERY ... 



