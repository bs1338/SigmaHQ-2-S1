# proc_creation_win_esentutl_sensitive_file_copy

## Title
Copying Sensitive Files with Credential Data

## ID
e7be6119-fc37-43f0-ad4f-1f3f99be2f9f

## Author
Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community

## Date
2019-10-22

## Tags
attack.credential-access, attack.t1003.002, attack.t1003.003, car.2013-07-001, attack.s0404

## Description
Files with well-known filenames (sensitive files with credential data) copying

## References
https://room362.com/post/2013/2013-06-10-volume-shadow-copy-ntdsdit-domain-hashes-remotely-part-1/
https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
https://dfironthemountain.wordpress.com/2018/12/06/locked-file-access-using-esentutl-exe/
https://github.com/LOLBAS-Project/LOLBAS/blob/2cc01b01132b5c304027a658c698ae09dd6a92bf/yml/OSBinaries/Esentutl.yml

## False Positives
Copying sensitive files for legitimate use (eg. backup) or forensic investigation by legitimate incident responder or forensic investigator.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "vss" OR TgtProcCmdLine containsCIS " -m " OR TgtProcCmdLine containsCIS " /m " OR TgtProcCmdLine containsCIS " â€“m " OR TgtProcCmdLine containsCIS " â€”m " OR TgtProcCmdLine containsCIS " â€•m " OR TgtProcCmdLine containsCIS " -y " OR TgtProcCmdLine containsCIS " /y " OR TgtProcCmdLine containsCIS " â€“y " OR TgtProcCmdLine containsCIS " â€”y " OR TgtProcCmdLine containsCIS " â€•y ") AND TgtProcImagePath endswithCIS "\esentutl.exe") OR (TgtProcCmdLine containsCIS "\config\RegBack\sam" OR TgtProcCmdLine containsCIS "\config\RegBack\security" OR TgtProcCmdLine containsCIS "\config\RegBack\system" OR TgtProcCmdLine containsCIS "\config\sam" OR TgtProcCmdLine containsCIS "\config\security" OR TgtProcCmdLine containsCIS "\config\system " OR TgtProcCmdLine containsCIS "\repair\sam" OR TgtProcCmdLine containsCIS "\repair\security" OR TgtProcCmdLine containsCIS "\repair\system" OR TgtProcCmdLine containsCIS "\windows\ntds\ntds.dit")))

```