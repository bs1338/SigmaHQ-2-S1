# file_event_win_susp_executable_creation

## Title
Suspicious Executable File Creation

## ID
74babdd6-a758-4549-9632-26535279e654

## Author
frack113

## Date
2022-09-05

## Tags
attack.defense-evasion, attack.t1564

## Description
Detect creation of suspicious executable file names.
Some strings look for suspicious file extensions, others look for filenames that exploit unquoted service paths.


## References
https://medium.com/@SumitVerma101/windows-privilege-escalation-part-1-unquoted-service-path-c7a011a8d8ae
https://app.any.run/tasks/76c69e2d-01e8-49d9-9aea-fb7cc0c4d3ad/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath endswithCIS ":\$Recycle.Bin.exe" OR TgtFilePath endswithCIS ":\Documents and Settings.exe" OR TgtFilePath endswithCIS ":\MSOCache.exe" OR TgtFilePath endswithCIS ":\PerfLogs.exe" OR TgtFilePath endswithCIS ":\Recovery.exe" OR TgtFilePath endswithCIS ".bat.exe" OR TgtFilePath endswithCIS ".sys.exe"))

```