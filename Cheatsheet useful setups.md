# Useful Setups

## Server:
#### Apache Server:
`sudo apt install apache2 `

#### FTP Server:
`apt-get install pure-ftpd`

`nano setup-pure-ftp`

```bash
    #!/bin/bash
    
    groupadd ftpgroup
    useradd -g ftpgroup -d /dev/null -s /etc ftpuser
    pure-pw useradd hacking -u ftpuser -d /ftphome
    pure-pw mkdb
    cd /etc/pure-ftpd/auth/
    ln -s ../conf/PureDB 60pdb
    mkdir -p /ftphome
    chown -R ftpuser:ftpgroup /ftphome/
    /etc/init.d/pure-ftpd restart
```

`chmod 755 setup-pure-ftp`

`./setup-pure-ftp`

## Environments:
#### Python 2 Environment:



## Others:

#### Bmap:
```bash
$ sudo apt-get install libc6-dev-i386
$ git clone https://github.com/CameronLonsdale/bmap.git
$ cd bmap
$ make
$ sudo cp bmap /sbin/bmap
```