# proc_creation_win_msdt_susp_parent

## Title
Suspicious MSDT Parent Process

## ID
7a74da6b-ea76-47db-92cc-874ad90df734

## Author
Nextron Systems

## Date
2022-06-01

## Tags
attack.defense-evasion, attack.t1036, attack.t1218

## Description
Detects msdt.exe executed by a suspicious parent as seen in CVE-2022-30190 / Follina exploitation

## References
https://twitter.com/nao_sec/status/1530196847679401984
https://app.any.run/tasks/713f05d2-fe78-4b9d-a744-f7c133e3fafb/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\msdt.exe" AND (SrcProcImagePath endswithCIS "\cmd.exe" OR SrcProcImagePath endswithCIS "\cscript.exe" OR SrcProcImagePath endswithCIS "\mshta.exe" OR SrcProcImagePath endswithCIS "\powershell.exe" OR SrcProcImagePath endswithCIS "\pwsh.exe" OR SrcProcImagePath endswithCIS "\regsvr32.exe" OR SrcProcImagePath endswithCIS "\rundll32.exe" OR SrcProcImagePath endswithCIS "\schtasks.exe" OR SrcProcImagePath endswithCIS "\wmic.exe" OR SrcProcImagePath endswithCIS "\wscript.exe" OR SrcProcImagePath endswithCIS "\wsl.exe")))

```