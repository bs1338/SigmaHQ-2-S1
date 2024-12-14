# registry_set_internet_explorer_disable_first_run_customize

## Title
Internet Explorer DisableFirstRunCustomize Enabled

## ID
ab567429-1dfb-4674-b6d2-979fd2f9d125

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-16

## Tags
attack.defense-evasion

## Description
Detects changes to the Internet Explorer "DisableFirstRunCustomize" value, which prevents Internet Explorer from running the first run wizard the first time a user starts the browser after installing Internet Explorer or Windows.


## References
https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/devil-bait/NCSC-MAR-Devil-Bait.pdf
https://unit42.paloaltonetworks.com/operation-ke3chang-resurfaces-with-new-tidepool-malware/
https://admx.help/?Category=InternetExplorer&Policy=Microsoft.Policies.InternetExplorer::NoFirstRunCustomise

## False Positives
As this is controlled by group policy as well as user settings. Some false positives may occur.

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (((RegistryValue In Contains AnyCase ("DWORD (0x00000001)","DWORD (0x00000002)")) AND RegistryKeyPath endswithCIS "\Microsoft\Internet Explorer\Main\DisableFirstRunCustomize") AND (NOT (SrcProcImagePath In Contains AnyCase ("C:\Windows\explorer.exe","C:\Windows\System32\ie4uinit.exe")))))

```