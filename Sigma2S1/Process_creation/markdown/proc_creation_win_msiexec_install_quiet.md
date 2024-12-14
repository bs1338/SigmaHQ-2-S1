# proc_creation_win_msiexec_install_quiet

## Title
Msiexec Quiet Installation

## ID
79a87aa6-e4bd-42fc-a5bb-5e6fbdcd62f5

## Author
frack113

## Date
2022-01-16

## Tags
attack.defense-evasion, attack.t1218.007

## Description
Adversaries may abuse msiexec.exe to proxy execution of malicious payloads.
 Msiexec.exe is the command-line utility for the Windows Installer and is thus commonly associated with executing installation packages (.msi)


## References
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/msiexec
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218.007/T1218.007.md
https://twitter.com/_st0pp3r_/status/1583914244344799235

## False Positives
WindowsApps installing updates via the quiet flag

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "-i" OR TgtProcCmdLine containsCIS "/i" OR TgtProcCmdLine containsCIS "â€“i" OR TgtProcCmdLine containsCIS "â€”i" OR TgtProcCmdLine containsCIS "â€•i" OR TgtProcCmdLine containsCIS "-package" OR TgtProcCmdLine containsCIS "/package" OR TgtProcCmdLine containsCIS "â€“package" OR TgtProcCmdLine containsCIS "â€”package" OR TgtProcCmdLine containsCIS "â€•package" OR TgtProcCmdLine containsCIS "-a" OR TgtProcCmdLine containsCIS "/a" OR TgtProcCmdLine containsCIS "â€“a" OR TgtProcCmdLine containsCIS "â€”a" OR TgtProcCmdLine containsCIS "â€•a" OR TgtProcCmdLine containsCIS "-j" OR TgtProcCmdLine containsCIS "/j" OR TgtProcCmdLine containsCIS "â€“j" OR TgtProcCmdLine containsCIS "â€”j" OR TgtProcCmdLine containsCIS "â€•j") AND TgtProcImagePath endswithCIS "\msiexec.exe" AND (TgtProcCmdLine containsCIS "-q" OR TgtProcCmdLine containsCIS "/q" OR TgtProcCmdLine containsCIS "â€“q" OR TgtProcCmdLine containsCIS "â€”q" OR TgtProcCmdLine containsCIS "â€•q")) AND (NOT (((TgtProcIntegrityLevel In ("System","S-1-16-16384")) AND SrcProcImagePath = "C:\Windows\CCM\Ccm32BitLauncher.exe") OR SrcProcImagePath startswithCIS "C:\Windows\Temp\" OR (SrcProcImagePath containsCIS "\AppData\Local\Temp\" AND SrcProcImagePath startswithCIS "C:\Users\")))))

```