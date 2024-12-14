# proc_creation_win_susp_ms_appinstaller_download

## Title
Potential File Download Via MS-AppInstaller Protocol Handler

## ID
180c7c5c-d64b-4a63-86e9-68910451bc8b

## Author
Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel

## Date
2023-11-09

## Tags
attack.defense-evasion, attack.execution, attack.t1218

## Description
Detects usage of the "ms-appinstaller" protocol handler via command line to potentially download arbitrary files via AppInstaller.EXE
The downloaded files are temporarly stored in ":\Users\%username%\AppData\Local\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\AC\INetCache\<RANDOM-8-CHAR-DIRECTORY>"


## References
https://lolbas-project.github.io/lolbas/Binaries/AppInstaller/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine = "*ms-appinstaller://*source=*" AND TgtProcCmdLine containsCIS "http"))

```