# proc_creation_win_reg_nolmhash

## Title
Enable LM Hash Storage - ProcCreation

## ID
98dedfdd-8333-49d4-9f23-d7018cccae53

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-12-15

## Tags
attack.defense-evasion, attack.t1112

## Description
Detects changes to the "NoLMHash" registry value in order to allow Windows to store LM Hashes.
By setting this registry value to "0" (DWORD), Windows will be allowed to store a LAN manager hash of your password in Active Directory and local SAM databases.


## References
https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/prevent-windows-store-lm-hash-password
https://www.sans.org/blog/protecting-privileged-domain-accounts-lm-hashes-the-good-the-bad-and-the-ugly/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "\System\CurrentControlSet\Control\Lsa" AND TgtProcCmdLine containsCIS "NoLMHash" AND TgtProcCmdLine containsCIS " 0"))

```