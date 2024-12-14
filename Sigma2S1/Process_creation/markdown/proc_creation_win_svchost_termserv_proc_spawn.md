# proc_creation_win_svchost_termserv_proc_spawn

## Title
Terminal Service Process Spawn

## ID
1012f107-b8f1-4271-af30-5aed2de89b39

## Author
Florian Roth (Nextron Systems)

## Date
2019-05-22

## Tags
attack.initial-access, attack.t1190, attack.lateral-movement, attack.t1210, car.2013-07-002

## Description
Detects a process spawned by the terminal service server process (this could be an indicator for an exploitation of CVE-2019-0708)

## References
https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/rdp-stands-for-really-do-patch-understanding-the-wormable-rdp-vulnerability-cve-2019-0708/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((SrcProcCmdLine containsCIS "\svchost.exe" AND SrcProcCmdLine containsCIS "termsvcs") AND (NOT ((TgtProcImagePath endswithCIS "\rdpclip.exe" OR TgtProcImagePath endswithCIS ":\Windows\System32\csrss.exe" OR TgtProcImagePath endswithCIS ":\Windows\System32\wininit.exe" OR TgtProcImagePath endswithCIS ":\Windows\System32\winlogon.exe") OR TgtProcImagePath IS NOT EMPTY))))

```