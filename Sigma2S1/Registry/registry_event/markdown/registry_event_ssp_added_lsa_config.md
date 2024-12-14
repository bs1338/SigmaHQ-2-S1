# registry_event_ssp_added_lsa_config

## Title
Security Support Provider (SSP) Added to LSA Configuration

## ID
eeb30123-9fbd-4ee8-aaa0-2e545bbed6dc

## Author
iwillkeepwatch

## Date
2019-01-18

## Tags
attack.persistence, attack.t1547.005

## Description
Detects the addition of a SSP to the registry. Upon a reboot or API call, SSP DLLs gain access to encrypted and plaintext passwords stored in Windows.


## References
https://powersploit.readthedocs.io/en/latest/Persistence/Install-SSP/
https://github.com/EmpireProject/Empire/blob/08cbd274bef78243d7a8ed6443b8364acd1fc48b/data/module_source/persistence/Install-SSP.ps1#L157

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath endswithCIS "\Control\Lsa\Security Packages" OR RegistryKeyPath endswithCIS "\Control\Lsa\OSConfig\Security Packages") AND (NOT (SrcProcImagePath In Contains AnyCase ("C:\Windows\system32\msiexec.exe","C:\Windows\syswow64\MsiExec.exe")))))

```