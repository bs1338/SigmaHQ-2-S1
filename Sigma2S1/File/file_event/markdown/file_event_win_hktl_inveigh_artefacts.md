# file_event_win_hktl_inveigh_artefacts

## Title
HackTool - Inveigh Execution Artefacts

## ID
bb09dd3e-2b78-4819-8e35-a7c1b874e449

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-10-24

## Tags
attack.command-and-control, attack.t1219

## Description
Detects the presence and execution of Inveigh via dropped artefacts

## References
https://github.com/Kevin-Robertson/Inveigh/blob/29d9e3c3a625b3033cdaf4683efaafadcecb9007/Inveigh/Support/Output.cs
https://github.com/Kevin-Robertson/Inveigh/blob/29d9e3c3a625b3033cdaf4683efaafadcecb9007/Inveigh/Support/Control.cs
https://thedfirreport.com/2020/11/23/pysa-mespinoza-ransomware/

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath endswithCIS "\Inveigh-Log.txt" OR TgtFilePath endswithCIS "\Inveigh-Cleartext.txt" OR TgtFilePath endswithCIS "\Inveigh-NTLMv1Users.txt" OR TgtFilePath endswithCIS "\Inveigh-NTLMv2Users.txt" OR TgtFilePath endswithCIS "\Inveigh-NTLMv1.txt" OR TgtFilePath endswithCIS "\Inveigh-NTLMv2.txt" OR TgtFilePath endswithCIS "\Inveigh-FormInput.txt" OR TgtFilePath endswithCIS "\Inveigh.dll" OR TgtFilePath endswithCIS "\Inveigh.exe" OR TgtFilePath endswithCIS "\Inveigh.ps1" OR TgtFilePath endswithCIS "\Inveigh-Relay.ps1"))

```