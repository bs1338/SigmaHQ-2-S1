# registry_set_disable_function_user

## Title
Disable Internal Tools or Feature in Registry

## ID
e2482f8d-3443-4237-b906-cc145d87a076

## Author
frack113, Nasreddine Bencherchali (Nextron Systems), CrimpSec

## Date
2022-03-18

## Tags
attack.defense-evasion, attack.t1112

## Description
Detects registry modifications that change features of internal Windows tools (malware like Agent Tesla uses this technique)

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1112/T1112.md
https://www.mandiant.com/resources/unc2165-shifts-to-evade-sanctions
https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html
https://www.malwarebytes.com/blog/detections/pum-optional-nodispbackgroundpage
https://www.malwarebytes.com/blog/detections/pum-optional-nodispcpl

## False Positives
Legitimate admin script

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryValue = "DWORD (0x00000000)" AND (RegistryKeyPath endswithCIS "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin" OR RegistryKeyPath endswithCIS "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\shutdownwithoutlogon" OR RegistryKeyPath endswithCIS "SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\ToastEnabled" OR RegistryKeyPath endswithCIS "SYSTEM\CurrentControlSet\Control\Storage\Write Protection" OR RegistryKeyPath endswithCIS "SYSTEM\CurrentControlSet\Control\StorageDevicePolicies\WriteProtect")) OR (RegistryValue = "DWORD (0x00000001)" AND (RegistryKeyPath endswithCIS "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\StartMenuLogOff" OR RegistryKeyPath endswithCIS "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableChangePassword" OR RegistryKeyPath endswithCIS "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableLockWorkstation" OR RegistryKeyPath endswithCIS "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableRegistryTools" OR RegistryKeyPath endswithCIS "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskmgr" OR RegistryKeyPath endswithCIS "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\NoDispBackgroundPage" OR RegistryKeyPath endswithCIS "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\NoDispCPL" OR RegistryKeyPath endswithCIS "SOFTWARE\Policies\Microsoft\Windows\Explorer\DisableNotificationCenter" OR RegistryKeyPath endswithCIS "SOFTWARE\Policies\Microsoft\Windows\System\DisableCMD"))))

```