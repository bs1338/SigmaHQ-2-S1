# file_event_win_ntds_dit_uncommon_parent_process

## Title
NTDS.DIT Creation By Uncommon Parent Process

## ID
4e7050dd-e548-483f-b7d6-527ab4fa784d

## Author
Florian Roth (Nextron Systems)

## Date
2022-03-11

## Tags
attack.credential-access, attack.t1003.003

## Description
Detects creation of a file named "ntds.dit" (Active Directory Database) by an uncommon parent process or directory

## References
https://www.ired.team/offensive-security/credential-access-and-credential-dumping/ntds.dit-enumeration
https://www.n00py.io/2022/03/manipulating-user-passwords-without-mimikatz/
https://pentestlab.blog/tag/ntds-dit/
https://github.com/samratashok/nishang/blob/414ee1104526d7057f9adaeee196d91ae447283e/Gather/Copy-VSS.ps1

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath endswithCIS "\ntds.dit" AND ((SrcProcParentImagePath endswithCIS "\cscript.exe" OR SrcProcParentImagePath endswithCIS "\httpd.exe" OR SrcProcParentImagePath endswithCIS "\nginx.exe" OR SrcProcParentImagePath endswithCIS "\php-cgi.exe" OR SrcProcParentImagePath endswithCIS "\powershell.exe" OR SrcProcParentImagePath endswithCIS "\pwsh.exe" OR SrcProcParentImagePath endswithCIS "\w3wp.exe" OR SrcProcParentImagePath endswithCIS "\wscript.exe") OR (SrcProcParentImagePath containsCIS "\apache" OR SrcProcParentImagePath containsCIS "\tomcat" OR SrcProcParentImagePath containsCIS "\AppData\" OR SrcProcParentImagePath containsCIS "\Temp\" OR SrcProcParentImagePath containsCIS "\Public\" OR SrcProcParentImagePath containsCIS "\PerfLogs\"))))

```