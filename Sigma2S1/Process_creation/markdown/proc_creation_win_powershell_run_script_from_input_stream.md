# proc_creation_win_powershell_run_script_from_input_stream

## Title
Run PowerShell Script from Redirected Input Stream

## ID
c83bf4b5-cdf0-437c-90fa-43d734f7c476

## Author
Moriarty Meng (idea), Anton Kutepov (rule), oscd.community

## Date
2020-10-17

## Tags
attack.defense-evasion, attack.execution, attack.t1059

## Description
Detects PowerShell script execution via input stream redirect

## References
https://github.com/LOLBAS-Project/LOLBAS/blob/4db780e0f0b2e2bb8cb1fa13e09196da9b9f1834/yml/LOLUtilz/OSBinaries/Powershell.yml
https://twitter.com/Moriarty_Meng/status/984380793383370752

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine RegExp "\\s-\\s*<" AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe")))

```