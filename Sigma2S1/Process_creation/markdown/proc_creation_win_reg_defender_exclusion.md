# proc_creation_win_reg_defender_exclusion

## Title
Suspicious Windows Defender Folder Exclusion Added Via Reg.EXE

## ID
48917adc-a28e-4f5d-b729-11e75da8941f

## Author
frack113

## Date
2022-02-13

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects the usage of "reg.exe" to add Defender folder exclusions. Qbot has been seen using this technique to add exclusions for folders within AppData and ProgramData.

## References
https://thedfirreport.com/2022/02/07/qbot-likes-to-move-it-move-it/
https://redcanary.com/threat-detection-report/threats/qbot/

## False Positives
Legitimate use

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" OR TgtProcCmdLine containsCIS "SOFTWARE\Microsoft\Microsoft Antimalware\Exclusions\Paths") AND (TgtProcCmdLine containsCIS "ADD " AND TgtProcCmdLine containsCIS "/t " AND TgtProcCmdLine containsCIS "REG_DWORD " AND TgtProcCmdLine containsCIS "/v " AND TgtProcCmdLine containsCIS "/d " AND TgtProcCmdLine containsCIS "0") AND TgtProcImagePath endswithCIS "\reg.exe"))

```