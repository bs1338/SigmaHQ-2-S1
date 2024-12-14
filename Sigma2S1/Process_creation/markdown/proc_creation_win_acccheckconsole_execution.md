# proc_creation_win_acccheckconsole_execution

## Title
Potential DLL Injection Via AccCheckConsole

## ID
0f6da907-5854-4be6-859a-e9958747b0aa

## Author
Florian Roth (Nextron Systems)

## Date
2022-01-06

## Tags
attack.execution, detection.threat-hunting

## Description
Detects the execution "AccCheckConsole" a command-line tool for verifying the accessibility implementation of an application's UI.
One of the tests that this checker can run are called "verification routine", which tests for things like Consistency, Navigation, etc.
The tool allows a user to provide a DLL that can contain a custom "verification routine". An attacker can build such DLLs and pass it via the CLI, which would then be loaded in the context of the "AccCheckConsole" utility.


## References
https://gist.github.com/bohops/2444129419c8acf837aedda5f0e7f340
https://twitter.com/bohops/status/1477717351017680899?s=12
https://lolbas-project.github.io/lolbas/OtherMSBinaries/AccCheckConsole/

## False Positives
Legitimate use of the UI Accessibility Checker

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -hwnd" OR TgtProcCmdLine containsCIS " -process " OR TgtProcCmdLine containsCIS " -window ") AND TgtProcImagePath endswithCIS "\AccCheckConsole.exe"))

```