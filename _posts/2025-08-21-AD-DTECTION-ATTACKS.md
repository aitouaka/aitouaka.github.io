---
title: "Detecting Windows Attacks with Splunk"
description: "A comprehensive guide on detecting Windows Active Directory attacks, lateral movements, Pass-the-Hash, Kerberoasting, Golden/Silver Tickets, Responder attacks, and other threats using Splunk and Zeek logs."
image: /images/Projects/splunkAD.png
date: 2025-08-21 22:00:00 +00:00
categories: [SOC]
tags: [active directory, splunk, zeek, detection, pentest, kerberos, pth, golden ticket, silver ticket, responder, pass-the-ticket, brute force]
---

## Domain Reconnaissance

For detection, administrators can employ PowerShell to monitor for unusual scripts or cmdlets and process command-line monitoring.

### User/Domain Reconnaissance Using BloodHound/SharpHound

The best option Windows can suggest is employing `Event 1644` - the LDAP performance monitoring log. Even with it enabled, BloodHound may not generate many of the expected events.

## Detecting User/Domain Recon With Splunk

```shell-session
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 earliest=1690447949 latest=1690450687
| search process_name IN (arp.exe,chcp.com,ipconfig.exe,net.exe,net1.exe,nltest.exe,ping.exe,systeminfo.exe,whoami.exe) OR (process_name IN (cmd.exe,powershell.exe) AND process IN (*arp*,*chcp*,*ipconfig*,*net*,*net1*,*nltest*,*ping*,*systeminfo*,*whoami*))
| stats values(process) as process, min(_time) as _time by parent_process, parent_process_id, dest, user
| where mvcount(process) > 3
````

### Detecting Recon By Targeting BloodHound

```shell-session
index=main earliest=1690195896 latest=1690285475 source="WinEventLog:SilkService-Log"
| spath input=Message 
| rename XmlEventData.* as * 
| table _time, ComputerName, ProcessName, ProcessId, DistinguishedName, SearchFilter
| sort 0 _time
| search SearchFilter="*(samAccountType=805306368)*"
| stats min(_time) as _time, max(_time) as maxTime, count, values(SearchFilter) as SearchFilter by ComputerName, ProcessName, ProcessId
| where count > 10
| convert ctime(maxTime)
```

## Password Spraying Detection Opportunities

A common pattern is multiple failed logon attempts with `Event ID 4625 - Failed Logon` from different user accounts but originating from the same source IP address within a short time frame.

Other event logs that may aid in password spraying detection include:

* `4768 and ErrorCode 0x6 - Kerberos Invalid Users`
* `4768 and ErrorCode 0x12 - Kerberos Disabled Users`
* `4776 and ErrorCode 0xC000006A - NTLM Invalid Users`
* `4776 and ErrorCode 0xC0000064 - NTLM Wrong Password`
* `4648 - Authenticate Using Explicit Credentials`
* `4771 - Kerberos Pre-Authentication Failed`

```shell-session
index=main earliest=1690280680 latest=1690289489 source="WinEventLog:Security" EventCode=4625
| bin span=15m _time
| stats values(user) as Users, dc(user) as dc_user by src, Source_Network_Address, dest, EventCode, Failure_Reason
```

## Detecting Responder-like Attacks

### Attack Steps:

* Victim device sends a name resolution query for a mistyped hostname (e.g., `fileshrae`).
* DNS fails to resolve the mistyped hostname.
* The victim device sends a name resolution query for the mistyped hostname using LLMNR/NBT-NS.
* The attacker's host responds to the LLMNR/NBT-NS traffic, pretending to know the identity of the requested host, effectively poisoning the service.

### Responder Detection Opportunities

* Deploy network monitoring solutions to detect unusual LLMNR and NBT-NS traffic patterns.
* Honeypot approach: name resolution for non-existent hosts should fail; success may indicate spoofing.
  [Praetorian Blog Reference](https://www.praetorian.com/blog/a-simple-and-effective-way-to-detect-broadcast-name-resolution-poisoning-bnrp/)

```shell-session
index=main earliest=1690290814 latest=1690291207 EventCode IN (4648) 
| table _time, EventCode, source, name, user, Target_Server_Name, Message
| sort 0 _time
```

```shell-session
index=main earliest=1690290078 latest=1690291207 EventCode=22 
| table _time, Computer, user, Image, QueryName, QueryResults
```

## Detecting Kerberoasting - TGS Requests

```shell-session
| spath input=Message 
| rename XmlEventData.* as * 
| table _time, ComputerName, ProcessName, DistinguishedName, SearchFilter 
| search SearchFilter="*(&(samAccountType=805306368)(servicePrincipalName=*)*"
```

```shell-session
index=main earliest=1690450374 latest=1690450483 EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)
| dedup RecordNumber
| rex field=user "(?<username>[^@]+)"
| bin span=2m _time 
| search username!=*$ 
| stats values(EventCode) as Events, values(service_name) as service_name, values(Additional_Information) as Additional_Information, values(Target_Server_Name) as Target_Server_Name by _time, username
| where !match(Events,"4648")
```

## Detecting AS-REPRoasting With Splunk

```shell-session
index=main earliest=1690392745 latest=1690393283 source="WinEventLog:SilkService-Log" 
| spath input=Message 
| rename XmlEventData.* as * 
| table _time, ComputerName, ProcessName, DistinguishedName, SearchFilter 
| search SearchFilter="*(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)*"
```

```shell-session
index=main earliest=1690392745 latest=1690393283 source="WinEventLog:Security" EventCode=4768 Pre_Authentication_Type=0
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip>[0-9\.]+)"
| table _time, src_ip, user, Pre_Authentication_Type, Ticket_Options, Ticket_Encryption_Type
```

## Pass-the-Hash

```shell-session
index=main earliest=1690450689 latest=1690451116 (source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="C:\\Windows\\system32\\lsass.exe" SourceImage!="C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\*\\MsMpEng.exe") OR (source="WinEventLog:Security" EventCode=4624 Logon_Type=9 Logon_Process=seclogo)
| sort _time, RecordNumber
| transaction host maxspan=1m endswith=(EventCode=4624) startswith=(EventCode=10)
| stats count by _time, Computer, SourceImage, SourceProcessId, Network_Account_Domain, Network_Account_Name, Logon_Type, Logon_Process
| fields - count
```

## Pass-the-Ticket

`Pass-the-Ticket (PtT)` is a lateral movement technique using Kerberos tickets instead of NTLM hashes, allowing attackers to move across network resources.

### Attack Steps:

* Extract valid TGT or TGS tickets from memory using tools like `Mimikatz` or `Rubeus`.
* Submit tickets for current logon session to authenticate elsewhere without passwords.

```shell-session
index=main earliest=1690392405 latest=1690451745 source="WinEventLog:Security" user!=*$ EventCode IN (4768,4769,4770) 
| rex field=user "(?<username>[^@]+)"
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip_4>[0-9\.]+)"
| transaction username, src_ip_4 maxspan=10h keepevicted=true startswith=(EventCode=4768)
| where closed_txn=0
| search NOT user="*$@*"
| table _time, ComputerName, username, src_ip_4, service_name, category
```

## Overpass-the-Hash

```shell-session
index=main earliest=1690443407 latest=1690443544 source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=3 dest_port=88 Image!=*lsass.exe) OR EventCode=1
| eventstats values(process) as process by process_id
| where EventCode=3
| stats count by _time, Computer, dest_ip, dest_port, Image, process
| fields - count
```

## Golden Ticket

```shell-session
index=main earliest=1690451977 latest=1690452262 source="WinEventLog:Security" user!=*$ EventCode IN (4768,4769,4770) 
| rex field=user "(?<username>[^@]+)"
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip_4>[0-9\.]+)"
| transaction username, src_ip_4 maxspan=10h keepevicted=true startswith=(EventCode=4768)
| where closed_txn=0
| search NOT user="*$@*"
| table _time, ComputerName, username, src_ip_4, service_name, category
```

## Silver Ticket

```shell-session
index=main latest=1690448444 EventCode=4720
| stats min(_time) as _time, values(EventCode) as EventCode by user
| outputlookup users.csv
```

## Detecting Unconstrained Delegation Attacks With Splunk

```shell-session
index=main earliest=1690544538 latest=1690544540 source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 Message="*TrustedForDelegation*" OR Message="*userAccountControl:1.2.840.113556.1.4.803:=524288*" 
| table _time, ComputerName, EventCode, Message
```

## Constrained Delegation

```shell-session
index=main earliest=1690544553 latest=1690562556 source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 Message="*msDS-AllowedToDelegateTo*" 
| table _time, ComputerName, EventCode, Message
```

## Detecting RDP Brute Force Attacks With Splunk & Zeek Logs

```shell-session
index="rdp_bruteforce" sourcetype="bro:rdp:json"
| bin _time span=5m
| stats count values(cookie) by _time, id.orig_h, id.resp_h
| where count>30
```

```shell-session
index="ssh_bruteforce" sourcetype="bro:ssh:json"
auth_success="false"
| bin _time span=5m
| stats sum(auth_attempts) as num_attempts by _time, id.orig_h, id.resp_h, client, server
| where num_attempts>30
```

## Detecting Beaconing Malware With Splunk & Zeek Logs

```shell-session
index="cobaltstrike_beacon" sourcetype="bro:http:json" 
| sort 0 _time
| streamstats current=f last(_time) as prevtime by src, dest, dest_port
| eval timedelta = _time - prevtime
| eventstats avg(timedelta) as avg, count as total by src, dest, dest_port
| eval upper=avg*1.1
| eval lower=avg*0.9
| where timedelta > lower AND timedelta < upper
| stats count, values(avg) as TimeInterval by src, dest, dest_port, total
| eval prcnt = (count/total)*100
| where prcnt > 90 AND total > 10
```

```shell-session
index="cobaltstrike_beacon" sourcetype="bro:http:json" src=10.0.10.20 dest=192.168.151.181
| timechart count
```

## Detecting Nmap Port Scanning With Splunk & Zeek Logs

```shell-session
index="cobaltstrike_beacon" sourcetype="bro:conn:json" orig_bytes=0 dest_ip IN (192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8) 
| bin span=5m _time 
| stats dc(dest_port) as num_dest_port by _time, src_ip, dest_ip 
| where num_dest_port >= 3
```

```shell-session
index="cobaltstrike_beacon" sourcetype="bro:conn:json" dest_ip IN (192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8) 
| bin span=5m _time
| stats dc(dest_port) as num_dest_port, values(dest_port) as dest_port by _time, src_ip, dest_ip
| where num_dest_port >= 3
```

## Detecting Kerberos Brute Force Attacks With Splunk & Zeek Logs

```shell-session
index="kerberos_bruteforce" sourcetype="bro:kerberos:json"
error_msg!=KDC_ERR_PREAUTH_REQUIRED
success="false" request_type=AS
| bin _time span=5m
| stats count dc(client) as "Unique users" values(error_msg) as "Error messages" by _time, id.orig_h, id.resp_h
| where count>30
```



## Detecting Kerberoasting With Splunk & Zeek Logs

Now let's explore how we can identify Kerberoasting, using Splunk and Zeek logs.

```shell-session
index="sharphound" sourcetype="bro:kerberos:json"
request_type=TGS cipher="rc4-hmac" 
forwardable="true" renewable="true"
| table _time, id.orig_h, id.resp_h, request_type, cipher, forwardable, renewable, client, service
````

## Detecting Golden Tickets With Splunk & Zeek Logs

Now let's explore how we can identify Golden Tickets, using Splunk and Zeek logs.

```shell-session
index="golden_ticket_attack" sourcetype="bro:kerberos:json"
| where client!="-"
| bin _time span=1m 
| stats values(client), values(request_type) as request_types, dc(request_type) as unique_request_types by _time, id.orig_h, id.resp_h
| where request_types=="TGS" AND unique_request_types==1
```

## Detecting Cobalt Strike's PSExec With Splunk & Zeek Logs

Now let's explore how we can identify Cobalt Strike's PSExec, using Splunk and Zeek logs.

```shell-session
index="cobalt_strike_psexec"
sourcetype="bro:smb_files:json"
action="SMB::FILE_OPEN" 
name IN ("*.exe", "*.dll", "*.bat")
path IN ("*\\c$", "*\\ADMIN$")
size>0
```

```shell-session
index="change_service_config" endpoint=svcctl sourcetype="bro:dce_rpc:json"
operation IN ("CreateServiceW", "CreateServiceA", "StartServiceW", "StartServiceA", "ChangeServiceConfigW")
| table _time, id.orig_h, id.resp_h, endpoint, operation
```

## Detecting Zerologon With Splunk & Zeek Logs

Now let's explore how we can identify Zerologon, using Splunk and Zeek logs.

```shell-session
index="zerologon" endpoint="netlogon" sourcetype="bro:dce_rpc:json"
| bin _time span=1m
| where operation == "NetrServerReqChallenge" OR operation == "NetrServerAuthenticate3" OR operation == "NetrServerPasswordSet2"
| stats count values(operation) as operation_values dc(operation) as unique_operations by _time, id.orig_h, id.resp_h
| where unique_operations >= 2 AND count>100
```

## Detecting HTTP Exfiltration With Splunk & Zeek Logs

Now let's explore how we can identify HTTP exfiltration, using Splunk and Zeek logs.

```shell-session
index="cobaltstrike_exfiltration_http" sourcetype="bro:http:json" method=POST
| stats sum(request_body_len) as TotalBytes by src, dest, dest_port
| eval TotalBytes = TotalBytes/1024/1024
```

