# proc_creation_win_lolbin_runexehelper

## Title
Lolbin Runexehelper Use As Proxy

## ID
cd71385d-fd9b-4691-9b98-2b1f7e508714

## Author
frack113

## Date
2022-12-29

## Tags
attack.defense-evasion, attack.t1218

## Description
Detect usage of the "runexehelper.exe" binary as a proxy to launch other programs

## References
https://twitter.com/0gtweet/status/1206692239839289344
https://lolbas-project.github.io/lolbas/Binaries/Runexehelper/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND SrcProcImagePath endswithCIS "\runexehelper.exe")

```