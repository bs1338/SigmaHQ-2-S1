# proc_creation_win_powershell_frombase64string

## Title
Base64 Encoded PowerShell Command Detected

## ID
e32d4572-9826-4738-b651-95fa63747e8a

## Author
Florian Roth (Nextron Systems)

## Date
2020-01-29

## Tags
attack.t1027, attack.defense-evasion, attack.t1140, attack.t1059.001

## Description
Detects usage of the "FromBase64String" function in the commandline which is used to decode a base64 encoded string

## References
https://gist.github.com/Neo23x0/6af876ee72b51676c82a2db8d2cd3639

## False Positives
Administrative script libraries

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcCmdLine containsCIS "::FromBase64String(")

```