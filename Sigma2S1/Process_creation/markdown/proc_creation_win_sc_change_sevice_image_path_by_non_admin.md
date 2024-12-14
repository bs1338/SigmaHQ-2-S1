# proc_creation_win_sc_change_sevice_image_path_by_non_admin

## Title
Possible Privilege Escalation via Weak Service Permissions

## ID
d937b75f-a665-4480-88a5-2f20e9f9b22a

## Author
Teymur Kheirkhabarov

## Date
2019-10-26

## Tags
attack.persistence, attack.defense-evasion, attack.privilege-escalation, attack.t1574.011

## Description
Detection of sc.exe utility spawning by user with Medium integrity level to change service ImagePath or FailureCommand

## References
https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
https://pentestlab.blog/2017/03/30/weak-service-permissions/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\sc.exe" AND (TgtProcIntegrityLevel In ("Medium","S-1-16-8192"))) AND ((TgtProcCmdLine containsCIS "config" AND TgtProcCmdLine containsCIS "binPath") OR (TgtProcCmdLine containsCIS "failure" AND TgtProcCmdLine containsCIS "command"))))

```