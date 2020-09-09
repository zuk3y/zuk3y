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

- check open ports on your localhost (sudo ss -tulwn | grep LISTEN)

- close unnecessary ports/services (sudo service <service name> stop)


[1. guide to secure kali](https://alphacybersecurity.tech/how-to-secure-your-kali-linux-machine/)

[2. guide to secure kali further](https://thehacktoday.com/how-to-protect-yourself-while-hacking-in-kali-linux/)

## the methodology i follow


- initial scoping

- recon 

- more recon

- enumerate all attack surfaces

- research the attack surfaces

- search for pre-existing exploits for the services

- create a personalised exploit

- exploit

- get a shell

- get a fully upgraded shell

- enumerate the target user/host

- escalate privileges

- gain root access

- submit flag/proof of concept

- write a report

- chill the fuvk out


## scoping
clearly understand which targets your have permission to scan/attack, do not break the law as it would hamper your reputation as a security researcher

## recon

the most important step of the methodology.
the better the recon, the larger the discovered attack surface, the higher the probability of finding a vulnerability and exploiting it.


### 1. masscan

fast full port scanner
```
masscan -i tun0 -p1-65535 --rate=1000 IP
```
  
### 2. nmap

this handy little tool lets you see which ports are open on the target along with other information about the target

```
nmap -sTV -v IP 


locate *.nse | grep <service>

sudo nmap -sS -sV --script=default,vuln -p- -T5 IP

nmap -p 139,445 --script=$scriptname IP

nmap -p 139,445 --script=smb-vuln* IP -v

nmap --script smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 IP

nmap -p 389 --script ldap-search IP
 ``` 

[list of useful ports](https://sushant747.gitbooks.io/total-oscp-guide/content/list_of_common_ports.html)

### 3. nikto 

heavy scanner that i seldom use due to massive data usage
```
nikto -host IP -port PORT
```
### 4. dirbuster

GUI, useful to check out directories on the target's port 80, finds directories hidden from plainview by bruteforcing it

### 5. wfuzz

CLI, useful to fuzz directories
```
wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/common.txt --hc 404,403 -u "http://IP/FUZZ.txt" -t 100

wfuzz -c -z range, 1-65535 http://IP/url.php?path=http://localhost:FUZZ
```
### 6. enum4linux

no shit, helps enumerate linux related services/targets

```
enum4inux -a IP
```

### 7.

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
