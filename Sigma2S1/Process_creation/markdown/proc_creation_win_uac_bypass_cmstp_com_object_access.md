# proc_creation_win_uac_bypass_cmstp_com_object_access

## Title
CMSTP UAC Bypass via COM Object Access

## ID
4b60e6f2-bf39-47b4-b4ea-398e33cfe253

## Author
Nik Seetharaman, Christian Burkard (Nextron Systems)

## Date
2019-07-31

## Tags
attack.execution, attack.defense-evasion, attack.privilege-escalation, attack.t1548.002, attack.t1218.003, attack.g0069, car.2019-04-001

## Description
Detects UAC Bypass Attempt Using Microsoft Connection Manager Profile Installer Autoelevate-capable COM Objects (e.g. UACMe ID of 41, 43, 58 or 65)

## References
https://web.archive.org/web/20190720093911/http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/
https://twitter.com/hFireF0X/status/897640081053364225
https://medium.com/falconforce/falconfriday-detecting-uac-bypasses-0xff16-86c2a9107abf
https://github.com/hfiref0x/UACME

## False Positives
Legitimate CMSTP use (unlikely in modern enterprise environments)

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcIntegrityLevel In ("High","System","S-1-16-16384","S-1-16-12288")) AND (SrcProcCmdLine containsCIS " /Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" OR SrcProcCmdLine containsCIS " /Processid:{3E000D72-A845-4CD9-BD83-80C07C3B881F}" OR SrcProcCmdLine containsCIS " /Processid:{BD54C901-076B-434E-B6C7-17C531F4AB41}" OR SrcProcCmdLine containsCIS " /Processid:{D2E7041B-2927-42FB-8E9F-7CE93B6DC937}" OR SrcProcCmdLine containsCIS " /Processid:{E9495B87-D950-4AB5-87A5-FF6D70BF3E90}") AND SrcProcImagePath endswithCIS "\DllHost.exe"))

```