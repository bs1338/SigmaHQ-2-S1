# proc_creation_win_uac_bypass_trustedpath

## Title
TrustedPath UAC Bypass Pattern

## ID
4ac47ed3-44c2-4b1f-9d51-bf46e8914126

## Author
Florian Roth (Nextron Systems)

## Date
2021-08-27

## Tags
attack.defense-evasion, attack.t1548.002

## Description
Detects indicators of a UAC bypass method by mocking directories

## References
https://medium.com/tenable-techblog/uac-bypass-by-mocking-trusted-directories-24a96675f6e
https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows
https://github.com/netero1010/TrustedPath-UACBypass-BOF

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcImagePath containsCIS "C:\Windows \System32\")

```