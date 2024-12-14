# proc_creation_win_office_outlook_susp_child_processes

## Title
Suspicious Outlook Child Process

## ID
208748f7-881d-47ac-a29c-07ea84bf691d

## Author
Michael Haag, Florian Roth (Nextron Systems), Markus Neis, Elastic, FPT.EagleEye Team

## Date
2022-02-28

## Tags
attack.execution, attack.t1204.002

## Description
Detects a suspicious process spawning from an Outlook process.

## References
https://www.hybrid-analysis.com/sample/465aabe132ccb949e75b8ab9c5bda36d80cf2fd503d52b8bad54e295f28bbc21?environmentId=100
https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\AppVLP.exe" OR TgtProcImagePath endswithCIS "\bash.exe" OR TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\forfiles.exe" OR TgtProcImagePath endswithCIS "\hh.exe" OR TgtProcImagePath endswithCIS "\mftrace.exe" OR TgtProcImagePath endswithCIS "\msbuild.exe" OR TgtProcImagePath endswithCIS "\msdt.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\msiexec.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\schtasks.exe" OR TgtProcImagePath endswithCIS "\scrcons.exe" OR TgtProcImagePath endswithCIS "\scriptrunner.exe" OR TgtProcImagePath endswithCIS "\sh.exe" OR TgtProcImagePath endswithCIS "\svchost.exe" OR TgtProcImagePath endswithCIS "\wmic.exe" OR TgtProcImagePath endswithCIS "\wscript.exe") AND SrcProcImagePath endswithCIS "\OUTLOOK.EXE"))

```