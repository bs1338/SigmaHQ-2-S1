# proc_creation_win_schtasks_schedule_via_masqueraded_xml_file

## Title
Suspicious Scheduled Task Creation via Masqueraded XML File

## ID
dd2a821e-3b07-4d3b-a9ac-929fe4c6ca0c

## Author
Swachchhanda Shrawan Poudel, Elastic (idea)

## Date
2023-04-20

## Tags
attack.defense-evasion, attack.persistence, attack.t1036.005, attack.t1053.005

## Description
Detects the creation of a scheduled task using the "-XML" flag with a file without the '.xml' extension. This behavior could be indicative of potential defense evasion attempt during persistence

## References
https://learn.microsoft.com/en-us/windows/win32/taskschd/daily-trigger-example--xml-
https://github.com/elastic/protections-artifacts/blob/084067123d3328a823b1c3fdde305b694275c794/behavior/rules/persistence_suspicious_scheduled_task_creation_via_masqueraded_xml_file.toml

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "/create" OR TgtProcCmdLine containsCIS "-create") AND (TgtProcCmdLine containsCIS "/xml" OR TgtProcCmdLine containsCIS "-xml") AND TgtProcImagePath endswithCIS "\schtasks.exe") AND (NOT (TgtProcCmdLine containsCIS ".xml" OR ((SrcProcCmdLine containsCIS ":\WINDOWS\Installer\MSI" AND SrcProcCmdLine containsCIS ".tmp,zzzzInvokeManagedCustomActionOutOfProc") AND SrcProcImagePath endswithCIS "\rundll32.exe") OR (TgtProcIntegrityLevel In ("System","S-1-16-16384")))) AND (NOT (SrcProcImagePath = "*:\ProgramData\OEM\UpgradeTool\CareCenter_*\BUnzip\Setup_msi.exe" OR SrcProcImagePath endswithCIS ":\Program Files\Axis Communications\AXIS Camera Station\SetupActions.exe" OR SrcProcImagePath endswithCIS ":\Program Files\Axis Communications\AXIS Device Manager\AdmSetupActions.exe" OR SrcProcImagePath endswithCIS ":\Program Files (x86)\Zemana\AntiMalware\AntiMalware.exe" OR SrcProcImagePath endswithCIS ":\Program Files\Dell\SupportAssist\pcdrcui.exe"))))

```