# proc_creation_win_ultravnc

## Title
Use of UltraVNC Remote Access Software

## ID
145322e4-0fd3-486b-81ca-9addc75736d8

## Author
frack113

## Date
2022-10-02

## Tags
attack.command-and-control, attack.t1219

## Description
An adversary may use legitimate desktop support and remote access software,to establish an interactive command and control channel to target systems within networks

## References
https://github.com/redcanaryco/atomic-red-team/blob/9e5b12c4912c07562aec7500447b11fa3e17e254/atomics/T1219/T1219.md

## False Positives
Legitimate use

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcDisplayName = "VNCViewer" OR TgtProcDisplayName = "UltraVNC VNCViewer" OR TgtProcPublisher = "UltraVNC"))

```