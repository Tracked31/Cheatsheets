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
| <span style="font-size: 12px;">HKEY_LOCAL_MACHINE\SAM | | <span style="font-size: 12px;">C:\Windows\system32\config\SAM |  | <span style="font-size: 12px;">Sam, Sam.log, Sam.sav | 
| <span style="font-size: 12px;">HKEY_LOCAL_MACHINE\SECURITY | | <span style="font-size: 12px;">C:\Windows\system32\config\SECURITY| | <span style="font-size: 12px;">Security, Security.log, Security.sav | 
| <span style="font-size: 12px;">HKEY_LOCAL_MACHINE\SOFTWARE |  | <span style="font-size: 12px;">C:\Windows\system32\config\SOFTWARE| | <span style="font-size: 12px;">Software, Software.log, Software.sav | 
| <span style="font-size: 12px;">HKEY_LOCAL_MACHINE\SYSTEM |  | <span style="font-size: 12px;">C:\Windows\system32\config\SYSTEM| | <span style="font-size: 12px;">System, System.alt, System.log, System.sav | 
| <span style="font-size: 12px;">HKEY_CURRENT_CONFIG |  || | <span style="font-size: 12px;">System, System.alt, System.log, System.sav, Ntuser.dat, Ntuser.dat.log| 
| <span style="font-size: 12px;">HKEY_USERS\DEFAULT | | <span style="font-size: 12px;">C:\Windows\system32\config\default | | <span style="font-size: 12px;">Default, Default.log Default.sav |
| | <span style="font-size: 12px;">System-/Computer-wide Configuration | | <span style="font-size: 12px;">%SystemRoot%\System32\config | |
| | <span style="font-size: 12px;">User-specific Configuration | | <span style="font-size: 12px;">%USERPROFILE%\NTUSER.dat | |
| <span style="font-size: 12px;">HKEY_USERS |  |  C:\Documents and Setting\User Profile\NTUSER.DAT| | | 
| <span style="font-size: 12px;">HKEY_LOCAL_MACHINE\Software\ <br>Microsoft\Windows\CurrentVersion\Run | <span style="font-size: 12px;">Autorun from programms | | | | 
| <span style="font-size: 12px;">HKEY_LOCAL_MACHINE\Software\ <br>Microsoft\Windows\CurrentVersion\RunOnce | <span style="font-size: 12px;">Autorun from programms | | | | 
| <span style="font-size: 12px;">HKEY_LOCAL_MACHINE\System\ <br>ControlSet00x\Enum\USBSTOR | <span style="font-size: 12px;">connected USB-devices | | | | 
| <span style="font-size: 12px;">HKEY_LOCAL_MACHINE\SOFTWARE\ <br>Microsoft\Windows NT\CurrentVersion\ <br>NetworkList\Profiles | <span style="font-size: 12px;">connected WLAN | | | | 
| <span style="font-size: 12px;">HKEY_CURRENT_USER\Software\ <br>Microsoft\Windows\CurrentVersion\ <br>Explorer\RecentDocs | <span style="font-size: 12px;">currently opened documents | | | |
| <span style="font-size: 12px;">HKEY_CURRENT_USER\software\ <br>microsoft\windows\currentversion\ <br>Explorer\RunMRU | <span style="font-size: 12px;">userlist | | | |



#### Tools:

RegRipper(sometimes wrong outputs -> not used in entreprises commonly):

```
rip.pl -r <HIVE> -p <plugin>
```
[Plugin - HIVE Pair database](https://hexacorn.com/tools/3r.html)

[Plugin Database](https://github.com/keydet89/RegRipper3.0)

regtime plugin to create timeline etc.

reg.exe QUERY ... 



