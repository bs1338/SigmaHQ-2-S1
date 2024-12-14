# proc_creation_win_rundll32_webdav_client_execution

## Title
WebDav Client Execution Via Rundll32.EXE

## ID
2dbd9d3d-9e27-42a8-b8df-f13825c6c3d5

## Author
Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)

## Date
2020-05-02

## Tags
attack.exfiltration, attack.t1048.003

## Description
Detects "svchost.exe" spawning "rundll32.exe" with command arguments like "C:\windows\system32\davclnt.dll,DavSetCookie".
This could be an indicator of exfiltration or use of WebDav to launch code (hosted on a WebDav server).


## References
https://github.com/OTRF/detection-hackathon-apt29/issues/17
https://github.com/OTRF/ThreatHunter-Playbook/blob/2d4257f630f4c9770f78d0c1df059f891ffc3fec/docs/evals/apt29/detections/7.B.4_C10730EA-6345-4934-AA0F-B0EFCA0C4BA6.md

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "C:\windows\system32\davclnt.dll,DavSetCookie" AND TgtProcImagePath endswithCIS "\rundll32.exe" AND SrcProcImagePath endswithCIS "\svchost.exe"))

```