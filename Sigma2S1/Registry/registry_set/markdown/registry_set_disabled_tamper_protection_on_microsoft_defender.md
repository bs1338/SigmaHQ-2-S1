# registry_set_disabled_tamper_protection_on_microsoft_defender

## Title
Disable Tamper Protection on Windows Defender

## ID
93d298a1-d28f-47f1-a468-d971e7796679

## Author
Austin Songer @austinsonger

## Date
2021-08-04

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects disabling Windows Defender Tamper Protection

## References
https://www.tenforums.com/tutorials/123792-turn-off-tamper-protection-microsoft-defender-antivirus.html

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryValue = "DWORD (0x00000000)" AND RegistryKeyPath containsCIS "\Microsoft\Windows Defender\Features\TamperProtection") AND (NOT ((SrcProcImagePath endswithCIS "\MsMpEng.exe" AND SrcProcImagePath startswithCIS "C:\ProgramData\Microsoft\Windows Defender\Platform\") OR SrcProcImagePath = "C:\Program Files\Windows Defender\MsMpEng.exe"))))

```