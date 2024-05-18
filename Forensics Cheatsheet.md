# 2024 Forensics Cheatsheet

## Table of Contents

**1. [General](#general)**

**2. [Disk forensics](#disk-forensics)**

* [Metadata](#metadata)
* [Disk backup](#disk-backup)
* [File system analysis](#file-system-analysis)

**3. [Operating system forensics](#operating-system-forensics)**

## 1. General

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
