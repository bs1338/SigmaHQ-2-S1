# proc_creation_win_msiexec_execute_dll

## Title
Suspicious Msiexec Execute Arbitrary DLL

## ID
6f4191bb-912b-48a8-9ce7-682769541e6d

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
https://twitter.com/_st0pp3r_/status/1583914515996897281

## False Positives
Legitimate script

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS " -y" OR TgtProcCmdLine containsCIS " /y" OR TgtProcCmdLine containsCIS " â€“y" OR TgtProcCmdLine containsCIS " â€”y" OR TgtProcCmdLine containsCIS " â€•y") AND TgtProcImagePath endswithCIS "\msiexec.exe") AND (NOT (TgtProcCmdLine containsCIS "\MsiExec.exe\" /Y \"C:\Program Files\Bonjour\mdnsNSP.dll" OR TgtProcCmdLine containsCIS "\MsiExec.exe\" /Y \"C:\Program Files (x86)\Bonjour\mdnsNSP.dll" OR TgtProcCmdLine containsCIS "\MsiExec.exe\" /Y \"C:\Program Files (x86)\Apple Software Update\ScriptingObjectModel.dll" OR TgtProcCmdLine containsCIS "\MsiExec.exe\" /Y \"C:\Program Files (x86)\Apple Software Update\SoftwareUpdateAdmin.dll" OR TgtProcCmdLine containsCIS "\MsiExec.exe\" /Y \"C:\Windows\CCM\" OR TgtProcCmdLine containsCIS "\MsiExec.exe\" /Y C:\Windows\CCM\" OR TgtProcCmdLine containsCIS "\MsiExec.exe\" -Y \"C:\Program Files\Bonjour\mdnsNSP.dll" OR TgtProcCmdLine containsCIS "\MsiExec.exe\" -Y \"C:\Program Files (x86)\Bonjour\mdnsNSP.dll" OR TgtProcCmdLine containsCIS "\MsiExec.exe\" -Y \"C:\Program Files (x86)\Apple Software Update\ScriptingObjectModel.dll" OR TgtProcCmdLine containsCIS "\MsiExec.exe\" -Y \"C:\Program Files (x86)\Apple Software Update\SoftwareUpdateAdmin.dll" OR TgtProcCmdLine containsCIS "\MsiExec.exe\" -Y \"C:\Windows\CCM\" OR TgtProcCmdLine containsCIS "\MsiExec.exe\" -Y C:\Windows\CCM\"))))

```