# proc_creation_win_dump64_defender_av_bypass_rename

## Title
Potential Windows Defender AV Bypass Via Dump64.EXE Rename

## ID
129966c9-de17-4334-a123-8b58172e664d

## Author
Austin Songer @austinsonger, Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2021-11-26

## Tags
attack.credential-access, attack.t1003.001

## Description
Detects when a user is potentially trying to bypass the Windows Defender AV by renaming a tool to dump64.exe and placing it in the Visual Studio folder.
 Currently the rule is covering only usage of procdump but other utilities can be added in order to increase coverage.


## References
https://twitter.com/mrd0x/status/1460597833917251595

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath containsCIS "\Microsoft Visual Studio\" AND TgtProcImagePath endswithCIS "\dump64.exe" AND TgtProcImagePath startswithCIS ":\Program Files") AND (TgtProcCmdLine containsCIS " -ma " OR TgtProcCmdLine containsCIS " -mp ")))

```