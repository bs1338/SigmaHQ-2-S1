# proc_creation_win_sdclt_child_process

## Title
Sdclt Child Processes

## ID
da2738f2-fadb-4394-afa7-0a0674885afa

## Author
Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)

## Date
2020-05-02

## Tags
attack.privilege-escalation, attack.t1548.002

## Description
A General detection for sdclt spawning new processes. This could be an indicator of sdclt being used for bypass UAC techniques.

## References
https://github.com/OTRF/detection-hackathon-apt29/issues/6
https://github.com/OTRF/ThreatHunter-Playbook/blob/2d4257f630f4c9770f78d0c1df059f891ffc3fec/docs/evals/apt29/detections/3.B.2_C36B49B5-DF58-4A34-9FE9-56189B9DEFEA.md

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND SrcProcImagePath endswithCIS "\sdclt.exe")

```