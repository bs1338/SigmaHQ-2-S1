# proc_creation_win_susp_use_of_vsjitdebugger_bin

## Title
Malicious PE Execution by Microsoft Visual Studio Debugger

## ID
15c7904e-6ad1-4a45-9b46-5fb25df37fd2

## Author
Agro (@agro_sev), Ensar Şamil (@sblmsrsn), oscd.community

## Date
2020-10-14

## Tags
attack.t1218, attack.defense-evasion

## Description
There is an option for a MS VS Just-In-Time Debugger "vsjitdebugger.exe" to launch specified executable and attach a debugger.
This option may be used adversaries to execute malicious code by signed verified binary.
The debugger is installed alongside with Microsoft Visual Studio package.


## References
https://twitter.com/pabraeken/status/990758590020452353
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Vsjitdebugger/
https://learn.microsoft.com/en-us/visualstudio/debugger/debug-using-the-just-in-time-debugger?view=vs-2019

## False Positives
The process spawned by vsjitdebugger.exe is uncommon.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\vsjitdebugger.exe" AND (NOT (TgtProcImagePath = "*\vsimmersiveactivatehelper*.exe" OR TgtProcImagePath endswithCIS "\devenv.exe"))))

```