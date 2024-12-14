# proc_creation_win_msxsl_execution

## Title
Msxsl.EXE Execution

## ID
9e50a8b3-dd05-4eb8-9153-bdb6b79d50b0

## Author
Timur Zinniatullin, oscd.community

## Date
2019-10-21

## Tags
attack.defense-evasion, attack.t1220

## Description
Detects the execution of the MSXSL utility. This can be used to execute Extensible Stylesheet Language (XSL) files. These files are commonly used to describe the processing and rendering of data within XML files.
Adversaries can abuse this functionality to execute arbitrary files while potentially bypassing application whitelisting defenses.


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1220/T1220.md
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Msxsl/

## False Positives
Msxsl is not installed by default and is deprecated, so unlikely on most systems.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcImagePath endswithCIS "\msxsl.exe")

```