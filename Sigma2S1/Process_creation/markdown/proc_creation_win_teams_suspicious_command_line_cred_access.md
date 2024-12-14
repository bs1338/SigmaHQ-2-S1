# proc_creation_win_teams_suspicious_command_line_cred_access

## Title
Potentially Suspicious Command Targeting Teams Sensitive Files

## ID
d2eb17db-1d39-41dc-b57f-301f6512fa75

## Author
@SerkinValery

## Date
2022-09-16

## Tags
attack.credential-access, attack.t1528

## Description
Detects a commandline containing references to the Microsoft Teams database or cookies files from a process other than Teams.
The database might contain authentication tokens and other sensitive information about the logged in accounts.


## References
https://www.bleepingcomputer.com/news/security/microsoft-teams-stores-auth-tokens-as-cleartext-in-windows-linux-macs/
https://www.vectra.ai/blogpost/undermining-microsoft-teams-security-by-mining-tokens

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "\Microsoft\Teams\Cookies" OR TgtProcCmdLine containsCIS "\Microsoft\Teams\Local Storage\leveldb") AND (NOT TgtProcImagePath endswithCIS "\Microsoft\Teams\current\Teams.exe")))

```