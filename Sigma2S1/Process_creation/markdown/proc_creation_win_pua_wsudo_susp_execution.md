# proc_creation_win_pua_wsudo_susp_execution

## Title
PUA - Wsudo Suspicious Execution

## ID
bdeeabc9-ff2a-4a51-be59-bb253aac7891

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-12-02

## Tags
attack.execution, attack.privilege-escalation, attack.t1059

## Description
Detects usage of wsudo (Windows Sudo Utility). Which is a tool that let the user execute programs with different permissions (System, Trusted Installer, Administrator...etc)

## References
https://github.com/M2Team/Privexec/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "-u System" OR TgtProcCmdLine containsCIS "-uSystem" OR TgtProcCmdLine containsCIS "-u TrustedInstaller" OR TgtProcCmdLine containsCIS "-uTrustedInstaller" OR TgtProcCmdLine containsCIS " --ti ") OR (TgtProcImagePath endswithCIS "\wsudo.exe" OR TgtProcDisplayName = "Windows sudo utility" OR SrcProcImagePath endswithCIS "\wsudo-bridge.exe")))

```