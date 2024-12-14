# file_event_win_ntds_exfil_tools

## Title
NTDS Exfiltration Filename Patterns

## ID
3a8da4e0-36c1-40d2-8b29-b3e890d5172a

## Author
Florian Roth (Nextron Systems)

## Date
2022-03-11

## Tags
attack.credential-access, attack.t1003.003

## Description
Detects creation of files with specific name patterns seen used in various tools that export the NTDS.DIT for exfiltration.

## References
https://github.com/rapid7/metasploit-framework/blob/eb6535009f5fdafa954525687f09294918b5398d/modules/post/windows/gather/ntds_grabber.rb
https://github.com/rapid7/metasploit-framework/blob/eb6535009f5fdafa954525687f09294918b5398d/data/post/powershell/NTDSgrab.ps1
https://github.com/SecureAuthCorp/impacket/blob/7d2991d78836b376452ca58b3d14daa61b67cb40/impacket/examples/secretsdump.py#L2405

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath endswithCIS "\All.cab" OR TgtFilePath endswithCIS ".ntds.cleartext"))

```