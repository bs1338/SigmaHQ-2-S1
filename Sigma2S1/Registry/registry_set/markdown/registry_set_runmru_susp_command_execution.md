# registry_set_runmru_susp_command_execution

## Title
Potentially Suspicious Command Executed Via Run Dialog Box - Registry

## ID
a7df0e9e-91a5-459a-a003-4cde67c2ff5d

## Author
Ahmed Farouk, Nasreddine Bencherchali

## Date
2024-11-01

## Tags
attack.execution, attack.t1059.001

## Description
Detects execution of commands via the run dialog box on Windows by checking values of the "RunMRU" registry key.
This technique was seen being abused by threat actors to deceive users into pasting and executing malicious commands, often disguised as CAPTCHA verification steps.


## References
https://medium.com/@ahmed.moh.farou2/fake-captcha-campaign-on-arabic-pirated-movie-sites-delivers-lumma-stealer-4f203f7adabf
https://medium.com/@shaherzakaria8/downloading-trojan-lumma-infostealer-through-capatcha-1f25255a0e71
https://www.forensafe.com/blogs/runmrukey.html
https://redcanary.com/blog/threat-intelligence/intelligence-insights-october-2024/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath containsCIS "\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" AND (((RegistryValue containsCIS "powershell" OR RegistryValue containsCIS "pwsh") AND (RegistryValue containsCIS " -e " OR RegistryValue containsCIS " -ec " OR RegistryValue containsCIS " -en " OR RegistryValue containsCIS " -enc " OR RegistryValue containsCIS " -enco" OR RegistryValue containsCIS "ftp" OR RegistryValue containsCIS "Hidden" OR RegistryValue containsCIS "http" OR RegistryValue containsCIS "iex" OR RegistryValue containsCIS "Invoke-")) OR (RegistryValue containsCIS "wmic" AND (RegistryValue containsCIS "shadowcopy" OR RegistryValue containsCIS "process call create")))))

```