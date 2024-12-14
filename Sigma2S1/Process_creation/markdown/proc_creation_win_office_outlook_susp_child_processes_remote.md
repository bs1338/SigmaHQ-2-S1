# proc_creation_win_office_outlook_susp_child_processes_remote

## Title
Suspicious Remote Child Process From Outlook

## ID
e212d415-0e93-435f-9e1a-f29005bb4723

## Author
Markus Neis, Nasreddine Bencherchali (Nextron Systems)

## Date
2018-12-27

## Tags
attack.execution, attack.t1059, attack.t1202

## Description
Detects a suspicious child process spawning from Outlook where the image is located in a remote location (SMB/WebDav shares).

## References
https://github.com/sensepost/ruler
https://www.fireeye.com/blog/threat-research/2018/12/overruled-containing-a-potentially-destructive-adversary.html
https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=49

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath startswithCIS "\\" AND SrcProcImagePath endswithCIS "\outlook.exe"))

```