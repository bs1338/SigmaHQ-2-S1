# proc_creation_win_susp_use_of_te_bin

## Title
Malicious Windows Script Components File Execution by TAEF Detection

## ID
634b00d5-ccc3-4a06-ae3b-0ec8444dd51b

## Author
Agro (@agro_sev) oscd.community

## Date
2020-10-13

## Tags
attack.defense-evasion, attack.t1218

## Description
Windows Test Authoring and Execution Framework (TAEF) framework allows you to run automation by executing tests files written on different languages (C, C#, Microsoft COM Scripting interfaces
Adversaries may execute malicious code (such as WSC file with VBScript, dll and so on) directly by running te.exe


## References
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Te/
https://twitter.com/pabraeken/status/993298228840992768
https://learn.microsoft.com/en-us/windows-hardware/drivers/taef/

## False Positives
It's not an uncommon to use te.exe directly to execute legal TAEF tests

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\te.exe" OR SrcProcImagePath endswithCIS "\te.exe"))

```