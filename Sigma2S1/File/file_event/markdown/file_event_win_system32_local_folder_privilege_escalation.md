# file_event_win_system32_local_folder_privilege_escalation

## Title
Potential Privilege Escalation Attempt Via .Exe.Local Technique

## ID
07a99744-56ac-40d2-97b7-2095967b0e03

## Author
Nasreddine Bencherchali (Nextron Systems), Subhash P (@pbssubhash)

## Date
2022-12-16

## Tags
attack.defense-evasion, attack.persistence, attack.privilege-escalation

## Description
Detects potential privilege escalation attempt via the creation of the "*.Exe.Local" folder inside the "System32" directory in order to sideload "comctl32.dll"

## References
https://github.com/binderlabs/DirCreate2System
https://github.com/sailay1996/awesome_windows_logical_bugs/blob/60cbb23a801f4c3195deac1cc46df27c225c3d07/dir_create2system.txt

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath endswithCIS "\comctl32.dll" AND (TgtFilePath startswithCIS "C:\Windows\System32\logonUI.exe.local" OR TgtFilePath startswithCIS "C:\Windows\System32\werFault.exe.local" OR TgtFilePath startswithCIS "C:\Windows\System32\consent.exe.local" OR TgtFilePath startswithCIS "C:\Windows\System32\narrator.exe.local" OR TgtFilePath startswithCIS "C:\Windows\System32\wermgr.exe.local")))

```