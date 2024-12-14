# proc_creation_win_ldifde_file_load

## Title
Import LDAP Data Interchange Format File Via Ldifde.EXE

## ID
6f535e01-ca1f-40be-ab8d-45b19c0c8b7f

## Author
@gott_cyber

## Date
2022-09-02

## Tags
attack.command-and-control, attack.defense-evasion, attack.t1218, attack.t1105

## Description
Detects the execution of "Ldifde.exe" with the import flag "-i" . The can be abused to include HTTP-based arguments which will allow the arbitrary download of files from a remote server.


## References
https://twitter.com/0gtweet/status/1564968845726580736
https://strontic.github.io/xcyclopedia/library/ldifde.exe-979DE101F5059CEC1D2C56967CA2BAC0.html
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731033(v=ws.11)

## False Positives
Since the content of the files are unknown, false positives are expected

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "-i" AND TgtProcCmdLine containsCIS "-f") AND TgtProcImagePath endswithCIS "\ldifde.exe"))

```