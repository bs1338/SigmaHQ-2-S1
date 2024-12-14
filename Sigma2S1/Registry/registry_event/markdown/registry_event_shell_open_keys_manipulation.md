# registry_event_shell_open_keys_manipulation

## Title
Shell Open Registry Keys Manipulation

## ID
152f3630-77c1-4284-bcc0-4cc68ab2f6e7

## Author
Christian Burkard (Nextron Systems)

## Date
2021-08-30

## Tags
attack.defense-evasion, attack.privilege-escalation, attack.t1548.002, attack.t1546.001

## Description
Detects the shell open key manipulation (exefile and ms-settings) used for persistence and the pattern of UAC Bypass using fodhelper.exe, computerdefaults.exe, slui.exe via registry keys (e.g. UACMe 33 or 62)

## References
https://github.com/hfiref0x/UACME
https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/
https://github.com/RhinoSecurityLabs/Aggressor-Scripts/tree/master/UACBypass
https://tria.ge/211119-gs7rtshcfr/behavioral2 [Lokibot sample from Nov 2021]

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryValue containsCIS "\Software\Classes\{" AND EventType = "SetValue" AND RegistryKeyPath endswithCIS "Classes\ms-settings\shell\open\command\SymbolicLinkValue") OR RegistryKeyPath endswithCIS "Classes\ms-settings\shell\open\command\DelegateExecute" OR ((EventType = "SetValue" AND (RegistryKeyPath endswithCIS "Classes\ms-settings\shell\open\command\(Default)" OR RegistryKeyPath endswithCIS "Classes\exefile\shell\open\command\(Default)")) AND (NOT RegistryValue = "(Empty)"))))

```