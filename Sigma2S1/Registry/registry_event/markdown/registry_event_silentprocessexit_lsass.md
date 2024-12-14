# registry_event_silentprocessexit_lsass

## Title
Potential Credential Dumping Via LSASS SilentProcessExit Technique

## ID
55e29995-75e7-451a-bef0-6225e2f13597

## Author
Florian Roth (Nextron Systems)

## Date
2021-02-26

## Tags
attack.credential-access, attack.t1003.001

## Description
Detects changes to the Registry in which a monitor program gets registered to dump the memory of the lsass.exe process

## References
https://www.deepinstinct.com/2021/02/16/lsass-memory-dumps-are-stealthier-than-ever-before-part-2/
https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND RegistryKeyPath containsCIS "Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe")

```