# proc_creation_win_susp_execution_path

## Title
Process Execution From A Potentially Suspicious Folder

## ID
3dfd06d2-eaf4-4532-9555-68aca59f57c4

## Author
Florian Roth (Nextron Systems), Tim Shelton

## Date
2019-01-16

## Tags
attack.defense-evasion, attack.t1036

## Description
Detects a potentially suspicious execution from an uncommon folder.

## References
https://github.com/mbevilacqua/appcompatprocessor/blob/6c847937c5a836e2ce2fe2b915f213c345a3c389/AppCompatSearch.txt
https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses
https://www.crowdstrike.com/resources/reports/2019-crowdstrike-global-threat-report/
https://github.com/ThreatHuntingProject/ThreatHunting/blob/cb22598bb70651f88e0285abc8d835757d2cb596/hunts/suspicious_process_creation_via_windows_event_logs.md

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath containsCIS ":\Perflogs\" OR TgtProcImagePath containsCIS ":\Users\All Users\" OR TgtProcImagePath containsCIS ":\Users\Default\" OR TgtProcImagePath containsCIS ":\Users\NetworkService\" OR TgtProcImagePath containsCIS ":\Windows\addins\" OR TgtProcImagePath containsCIS ":\Windows\debug\" OR TgtProcImagePath containsCIS ":\Windows\Fonts\" OR TgtProcImagePath containsCIS ":\Windows\Help\" OR TgtProcImagePath containsCIS ":\Windows\IME\" OR TgtProcImagePath containsCIS ":\Windows\Media\" OR TgtProcImagePath containsCIS ":\Windows\repair\" OR TgtProcImagePath containsCIS ":\Windows\security\" OR TgtProcImagePath containsCIS ":\Windows\System32\Tasks\" OR TgtProcImagePath containsCIS ":\Windows\Tasks\" OR TgtProcImagePath containsCIS "$Recycle.bin" OR TgtProcImagePath containsCIS "\config\systemprofile\" OR TgtProcImagePath containsCIS "\Intel\Logs\" OR TgtProcImagePath containsCIS "\RSA\MachineKeys\") AND (NOT ((TgtProcImagePath endswithCIS "\CitrixReceiverUpdater.exe" AND TgtProcImagePath startswithCIS "C:\Windows\SysWOW64\config\systemprofile\Citrix\UpdaterBinaries\") OR TgtProcImagePath startswithCIS "C:\Users\Public\IBM\ClientSolutions\Start_Programs\"))))

```