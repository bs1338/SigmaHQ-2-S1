# file_event_win_office_susp_file_extension

## Title
File With Uncommon Extension Created By An Office Application

## ID
c7a74c80-ba5a-486e-9974-ab9e682bc5e4

## Author
Vadim Khrykov (ThreatIntel), Cyb3rEng (Rule), Nasreddine Bencherchali (Nextron Systems)

## Date
2021-08-23

## Tags
attack.t1204.002, attack.execution

## Description
Detects the creation of files with an executable or script extension by an Office application.

## References
https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/
https://github.com/vadim-hunter/Detection-Ideas-Rules/blob/02bcbfc2bfb8b4da601bb30de0344ae453aa1afe/Threat%20Intelligence/The%20DFIR%20Report/20210329_Sodinokibi_(aka_REvil)_Ransomware.yaml

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (((SrcProcImagePath endswithCIS "\excel.exe" OR SrcProcImagePath endswithCIS "\msaccess.exe" OR SrcProcImagePath endswithCIS "\mspub.exe" OR SrcProcImagePath endswithCIS "\powerpnt.exe" OR SrcProcImagePath endswithCIS "\visio.exe" OR SrcProcImagePath endswithCIS "\winword.exe") AND (TgtFilePath endswithCIS ".bat" OR TgtFilePath endswithCIS ".cmd" OR TgtFilePath endswithCIS ".com" OR TgtFilePath endswithCIS ".dll" OR TgtFilePath endswithCIS ".exe" OR TgtFilePath endswithCIS ".hta" OR TgtFilePath endswithCIS ".ocx" OR TgtFilePath endswithCIS ".proj" OR TgtFilePath endswithCIS ".ps1" OR TgtFilePath endswithCIS ".scf" OR TgtFilePath endswithCIS ".scr" OR TgtFilePath endswithCIS ".sys" OR TgtFilePath endswithCIS ".vbe" OR TgtFilePath endswithCIS ".vbs" OR TgtFilePath endswithCIS ".wsf" OR TgtFilePath endswithCIS ".wsh")) AND (NOT (TgtFilePath containsCIS "\AppData\Local\assembly\tmp\" AND TgtFilePath endswithCIS ".dll")) AND (NOT ((SrcProcImagePath endswithCIS "\winword.exe" AND TgtFilePath containsCIS "\AppData\Local\Temp\webexdelta\" AND (TgtFilePath endswithCIS ".dll" OR TgtFilePath endswithCIS ".exe")) OR ((TgtFilePath containsCIS "C:\Users\" AND TgtFilePath containsCIS "\AppData\Local\Microsoft\Office\" AND TgtFilePath containsCIS "\WebServiceCache\AllUsers") AND TgtFilePath endswithCIS ".com")))))

```