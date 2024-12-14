# file_event_win_susp_desktop_txt

## Title
Suspicious Creation TXT File in User Desktop

## ID
caf02a0a-1e1c-4552-9b48-5e070bd88d11

## Author
frack113

## Date
2021-12-26

## Tags
attack.impact, attack.t1486

## Description
Ransomware create txt file in the user Desktop

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1486/T1486.md#atomic-test-5---purelocker-ransom-note

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\cmd.exe" AND (TgtFilePath containsCIS "\Users\" AND TgtFilePath containsCIS "\Desktop\") AND TgtFilePath endswithCIS ".txt"))

```