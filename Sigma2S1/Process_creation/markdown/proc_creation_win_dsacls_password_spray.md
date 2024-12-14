# proc_creation_win_dsacls_password_spray

## Title
Potential Password Spraying Attempt Using Dsacls.EXE

## ID
bac9fb54-2da7-44e9-988f-11e9a5edbc0c

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-06-20

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects possible password spraying attempts using Dsacls

## References
https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/using-dsacls-to-check-ad-object-permissions#password-spraying-anyone
https://ss64.com/nt/dsacls.html
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771151(v=ws.11)

## False Positives
Legitimate use of dsacls to bind to an LDAP session

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "/user:" AND TgtProcCmdLine containsCIS "/passwd:") AND TgtProcImagePath endswithCIS "\dsacls.exe"))

```