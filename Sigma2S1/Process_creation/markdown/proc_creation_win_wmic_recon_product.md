# proc_creation_win_wmic_recon_product

## Title
Potential Product Reconnaissance Via Wmic.EXE

## ID
15434e33-5027-4914-88d5-3d4145ec25a9

## Author
Nasreddine Bencherchali

## Date
2023-02-14

## Tags
attack.execution, attack.t1047

## Description
Detects the execution of WMIC in order to get a list of firewall and antivirus products

## References
https://thedfirreport.com/2023/03/06/2022-year-in-review/
https://www.yeahhub.com/list-installed-programs-version-path-windows/
https://learn.microsoft.com/en-us/answers/questions/253555/software-list-inventory-wmic-product

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "Product" AND TgtProcImagePath endswithCIS "\wmic.exe"))

```