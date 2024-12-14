# registry_set_dsrm_tampering

## Title
Directory Service Restore Mode(DSRM) Registry Value Tampering

## ID
b61e87c0-50db-4b2e-8986-6a2be94b33b0

## Author
Nischal Khadgi

## Date
2024-07-11

## Tags
attack.persistence, attack.t1556

## Description
Detects changes to "DsrmAdminLogonBehavior" registry value.
During a Domain Controller (DC) promotion, administrators create a Directory Services Restore Mode (DSRM) local administrator account with a password that rarely changes. The DSRM account is an “Administrator” account that logs in with the DSRM mode when the server is booting up to restore AD backups or recover the server from a failure.
 Attackers could abuse DSRM account to maintain their persistence and access to the organization's Active Directory.
If the "DsrmAdminLogonBehavior" value is set to "0", the administrator account can only be used if the DC starts in DSRM.
 If the "DsrmAdminLogonBehavior" value is set to "1", the administrator account can only be used if the local AD DS service is stopped.
If the "DsrmAdminLogonBehavior" value is set to "2", the administrator account can always be used.


## References
https://adsecurity.org/?p=1785
https://www.sentinelone.com/blog/detecting-dsrm-account-misconfigurations/
https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/dsrm-credentials

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath endswithCIS "\Control\Lsa\DsrmAdminLogonBehavior" AND (NOT RegistryValue = "DWORD (0x00000000)")))

```