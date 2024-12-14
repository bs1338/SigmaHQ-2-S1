# proc_creation_win_java_sysaidserver_susp_child_process

## Title
Suspicious SysAidServer Child

## ID
60bfeac3-0d35-4302-8efb-1dd16f715bc6

## Author
Florian Roth (Nextron Systems)

## Date
2022-08-26

## Tags
attack.lateral-movement, attack.t1210

## Description
Detects suspicious child processes of SysAidServer (as seen in MERCURY threat actor intrusions)

## References
https://www.microsoft.com/security/blog/2022/08/25/mercury-leveraging-log4j-2-vulnerabilities-in-unpatched-systems-to-target-israeli-organizations/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (SrcProcCmdLine containsCIS "SysAidServer" AND (SrcProcImagePath endswithCIS "\java.exe" OR SrcProcImagePath endswithCIS "\javaw.exe")))

```