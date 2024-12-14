# proc_creation_win_schtasks_change

## Title
Suspicious Modification Of Scheduled Tasks

## ID
1c0e41cd-21bb-4433-9acc-4a2cd6367b9b

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-28

## Tags
attack.execution, attack.t1053.005

## Description
Detects when an attacker tries to modify an already existing scheduled tasks to run from a suspicious location
Attackers can create a simple looking task in order to avoid detection on creation as it's often the most focused on
Instead they modify the task after creation to include their malicious payload


## References
Internal Research
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS " /Change " AND TgtProcCmdLine containsCIS " /TN ") AND TgtProcImagePath endswithCIS "\schtasks.exe") AND (TgtProcCmdLine containsCIS "regsvr32" OR TgtProcCmdLine containsCIS "rundll32" OR TgtProcCmdLine containsCIS "cmd /c " OR TgtProcCmdLine containsCIS "cmd /k " OR TgtProcCmdLine containsCIS "cmd /r " OR TgtProcCmdLine containsCIS "cmd.exe /c " OR TgtProcCmdLine containsCIS "cmd.exe /k " OR TgtProcCmdLine containsCIS "cmd.exe /r " OR TgtProcCmdLine containsCIS "powershell" OR TgtProcCmdLine containsCIS "mshta" OR TgtProcCmdLine containsCIS "wscript" OR TgtProcCmdLine containsCIS "cscript" OR TgtProcCmdLine containsCIS "certutil" OR TgtProcCmdLine containsCIS "bitsadmin" OR TgtProcCmdLine containsCIS "bash.exe" OR TgtProcCmdLine containsCIS "bash " OR TgtProcCmdLine containsCIS "scrcons" OR TgtProcCmdLine containsCIS "wmic " OR TgtProcCmdLine containsCIS "wmic.exe" OR TgtProcCmdLine containsCIS "forfiles" OR TgtProcCmdLine containsCIS "scriptrunner" OR TgtProcCmdLine containsCIS "hh.exe" OR TgtProcCmdLine containsCIS "hh ") AND (TgtProcCmdLine containsCIS "\AppData\Local\Temp" OR TgtProcCmdLine containsCIS "\AppData\Roaming\" OR TgtProcCmdLine containsCIS "\Users\Public\" OR TgtProcCmdLine containsCIS "\WINDOWS\Temp\" OR TgtProcCmdLine containsCIS "\Desktop\" OR TgtProcCmdLine containsCIS "\Downloads\" OR TgtProcCmdLine containsCIS "\Temporary Internet" OR TgtProcCmdLine containsCIS "C:\ProgramData\" OR TgtProcCmdLine containsCIS "C:\Perflogs\" OR TgtProcCmdLine containsCIS "%ProgramData%" OR TgtProcCmdLine containsCIS "%appdata%" OR TgtProcCmdLine containsCIS "%comspec%" OR TgtProcCmdLine containsCIS "%localappdata%")))

```