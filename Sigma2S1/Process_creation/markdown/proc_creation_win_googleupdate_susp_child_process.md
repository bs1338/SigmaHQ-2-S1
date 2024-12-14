# proc_creation_win_googleupdate_susp_child_process

## Title
Potentially Suspicious GoogleUpdate Child Process

## ID
84b1ecf9-6eff-4004-bafb-bae5c0e251b2

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-15

## Tags
attack.defense-evasion

## Description
Detects potentially suspicious child processes of "GoogleUpdate.exe"

## References
https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/goofy-guineapig/NCSC-MAR-Goofy-Guineapig.pdf

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\GoogleUpdate.exe" AND (NOT (TgtProcImagePath IS NOT EMPTY OR (TgtProcImagePath containsCIS "\Google" OR (TgtProcImagePath endswithCIS "\setup.exe" OR TgtProcImagePath endswithCIS "chrome_updater.exe" OR TgtProcImagePath endswithCIS "chrome_installer.exe"))))))

```