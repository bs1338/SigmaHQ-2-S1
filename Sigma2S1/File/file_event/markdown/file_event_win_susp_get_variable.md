# file_event_win_susp_get_variable

## Title
Suspicious Get-Variable.exe Creation

## ID
0c3fac91-5627-46e8-a6a8-a0d7b9b8ae1b

## Author
frack113

## Date
2022-04-23

## Tags
attack.persistence, attack.t1546, attack.defense-evasion, attack.t1027

## Description
Get-Variable is a valid PowerShell cmdlet
WindowsApps is by default in the path where PowerShell is executed.
So when the Get-Variable command is issued on PowerShell execution, the system first looks for the Get-Variable executable in the path and executes the malicious binary instead of looking for the PowerShell cmdlet.


## References
https://blog.malwarebytes.com/threat-intelligence/2022/04/colibri-loader-combines-task-scheduler-and-powershell-in-clever-persistence-technique/
https://www.joesandbox.com/analysis/465533/0/html

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND TgtFilePath endswithCIS "Local\Microsoft\WindowsApps\Get-Variable.exe")

```