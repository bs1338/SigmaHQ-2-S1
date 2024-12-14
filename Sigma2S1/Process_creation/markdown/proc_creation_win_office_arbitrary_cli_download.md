# proc_creation_win_office_arbitrary_cli_download

## Title
Potential Arbitrary File Download Using Office Application

## ID
4ae3e30b-b03f-43aa-87e3-b622f4048eed

## Author
Nasreddine Bencherchali (Nextron Systems), Beyu Denis, oscd.community

## Date
2022-05-17

## Tags
attack.defense-evasion, attack.t1202

## Description
Detects potential arbitrary file download using a Microsoft Office application

## References
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Winword/
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Powerpnt/
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Excel/
https://medium.com/@reegun/unsanitized-file-validation-leads-to-malicious-payload-download-via-office-binaries-202d02db7191

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "http://" OR TgtProcCmdLine containsCIS "https://") AND (TgtProcImagePath endswithCIS "\EXCEL.EXE" OR TgtProcImagePath endswithCIS "\POWERPNT.EXE" OR TgtProcImagePath endswithCIS "\WINWORD.exe")))

```