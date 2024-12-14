# file_event_win_dll_sideloading_space_path

## Title
DLL Search Order Hijackig Via Additional Space in Path

## ID
b6f91281-20aa-446a-b986-38a92813a18f

## Author
frack113, Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-30

## Tags
attack.persistence, attack.privilege-escalation, attack.defense-evasion, attack.t1574.002

## Description
Detects when an attacker create a similar folder structure to windows system folders such as (Windows, Program Files...)
but with a space in order to trick DLL load search order and perform a "DLL Search Order Hijacking" attack


## References
https://twitter.com/cyb3rops/status/1552932770464292864
https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath endswithCIS ".dll" AND (TgtFilePath startswithCIS "C:\Windows \" OR TgtFilePath startswithCIS "C:\Program Files \" OR TgtFilePath startswithCIS "C:\Program Files (x86) \")))

```