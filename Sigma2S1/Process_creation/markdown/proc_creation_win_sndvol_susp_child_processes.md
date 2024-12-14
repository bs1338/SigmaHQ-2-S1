# proc_creation_win_sndvol_susp_child_processes

## Title
Uncommon Child Processes Of SndVol.exe

## ID
ba42babc-0666-4393-a4f7-ceaf5a69191e

## Author
X__Junior (Nextron Systems)

## Date
2023-06-09

## Tags
attack.execution

## Description
Detects potentially uncommon child processes of SndVol.exe (the Windows volume mixer)

## References
https://twitter.com/Max_Mal_/status/1661322732456353792

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\SndVol.exe" AND (NOT (TgtProcCmdLine containsCIS " shell32.dll,Control_RunDLL " AND TgtProcImagePath endswithCIS "\rundll32.exe"))))

```