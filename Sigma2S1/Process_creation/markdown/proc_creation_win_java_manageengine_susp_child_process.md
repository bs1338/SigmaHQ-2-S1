# proc_creation_win_java_manageengine_susp_child_process

## Title
Suspicious Child Process Of Manage Engine ServiceDesk

## ID
cea2b7ea-792b-405f-95a1-b903ea06458f

## Author
Florian Roth (Nextron Systems)

## Date
2023-01-18

## Tags
attack.command-and-control, attack.t1102

## Description
Detects suspicious child processes of the "Manage Engine ServiceDesk Plus" Java web service

## References
https://www.horizon3.ai/manageengine-cve-2022-47966-technical-deep-dive/
https://github.com/horizon3ai/CVE-2022-47966/blob/3a51c6b72ebbd87392babd955a8fbeaee2090b35/CVE-2022-47966.py
https://blog.viettelcybersecurity.com/saml-show-stopper/

## False Positives
Legitimate sub processes started by Manage Engine ServiceDesk Pro

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcImagePath endswithCIS "\AppVLP.exe" OR TgtProcImagePath endswithCIS "\bash.exe" OR TgtProcImagePath endswithCIS "\bitsadmin.exe" OR TgtProcImagePath endswithCIS "\calc.exe" OR TgtProcImagePath endswithCIS "\certutil.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\curl.exe" OR TgtProcImagePath endswithCIS "\forfiles.exe" OR TgtProcImagePath endswithCIS "\mftrace.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\net.exe" OR TgtProcImagePath endswithCIS "\net1.exe" OR TgtProcImagePath endswithCIS "\notepad.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\query.exe" OR TgtProcImagePath endswithCIS "\reg.exe" OR TgtProcImagePath endswithCIS "\schtasks.exe" OR TgtProcImagePath endswithCIS "\scrcons.exe" OR TgtProcImagePath endswithCIS "\sh.exe" OR TgtProcImagePath endswithCIS "\systeminfo.exe" OR TgtProcImagePath endswithCIS "\whoami.exe" OR TgtProcImagePath endswithCIS "\wmic.exe" OR TgtProcImagePath endswithCIS "\wscript.exe") AND (SrcProcImagePath containsCIS "\ManageEngine\ServiceDesk\" AND SrcProcImagePath containsCIS "\java.exe")) AND (NOT (TgtProcCmdLine containsCIS " stop" AND (TgtProcImagePath endswithCIS "\net.exe" OR TgtProcImagePath endswithCIS "\net1.exe")))))

```