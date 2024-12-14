# proc_creation_win_bitsadmin_potential_persistence

## Title
Monitoring For Persistence Via BITS

## ID
b9cbbc17-d00d-4e3d-a827-b06d03d2380d

## Author
Sreeman

## Date
2020-10-29

## Tags
attack.defense-evasion, attack.t1197

## Description
BITS will allow you to schedule a command to execute after a successful download to notify you that the job is finished.
When the job runs on the system the command specified in the BITS job will be executed.
This can be abused by actors to create a backdoor within the system and for persistence.
It will be chained in a BITS job to schedule the download of malware/additional binaries and execute the program after being downloaded.


## References
https://www.fireeye.com/blog/threat-research/2020/10/kegtap-and-singlemalt-with-a-ransomware-chaser.html
http://0xthem.blogspot.com/2014/03/t-emporal-persistence-with-and-schtasks.html
https://isc.sans.edu/diary/Wipe+the+drive+Stealthy+Malware+Persistence+Mechanism+-+Part+1/15394

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\bitsadmin.exe" AND ((TgtProcCmdLine containsCIS "/SetNotifyCmdLine" AND (TgtProcCmdLine containsCIS "%COMSPEC%" OR TgtProcCmdLine containsCIS "cmd.exe" OR TgtProcCmdLine containsCIS "regsvr32.exe")) OR (TgtProcCmdLine containsCIS "/Addfile" AND (TgtProcCmdLine containsCIS "http:" OR TgtProcCmdLine containsCIS "https:" OR TgtProcCmdLine containsCIS "ftp:" OR TgtProcCmdLine containsCIS "ftps:")))))

```