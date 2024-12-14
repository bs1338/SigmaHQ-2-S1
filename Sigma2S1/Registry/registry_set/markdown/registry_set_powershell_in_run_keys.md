# registry_set_powershell_in_run_keys

## Title
Suspicious Powershell In Registry Run Keys

## ID
8d85cf08-bf97-4260-ba49-986a2a65129c

## Author
frack113, Florian Roth (Nextron Systems)

## Date
2022-03-17

## Tags
attack.persistence, attack.t1547.001

## Description
Detects potential PowerShell commands or code within registry run keys

## References
https://github.com/frack113/atomic-red-team/blob/a9051c38de8a5320b31c7039efcbd3b56cf2d65a/atomics/T1547.001/T1547.001.md#atomic-test-9---systembc-malware-as-a-service-registry
https://www.trendmicro.com/en_us/research/22/j/lv-ransomware-exploits-proxyshell-in-attack.html

## False Positives
Legitimate admin or third party scripts. Baseline according to your environment

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryValue containsCIS "powershell" OR RegistryValue containsCIS "pwsh " OR RegistryValue containsCIS "FromBase64String" OR RegistryValue containsCIS ".DownloadFile(" OR RegistryValue containsCIS ".DownloadString(" OR RegistryValue containsCIS " -w hidden " OR RegistryValue containsCIS " -w 1 " OR RegistryValue containsCIS "-windowstyle hidden" OR RegistryValue containsCIS "-window hidden" OR RegistryValue containsCIS " -nop " OR RegistryValue containsCIS " -encodedcommand " OR RegistryValue containsCIS "-ExecutionPolicy Bypass" OR RegistryValue containsCIS "Invoke-Expression" OR RegistryValue containsCIS "IEX (" OR RegistryValue containsCIS "Invoke-Command" OR RegistryValue containsCIS "ICM -" OR RegistryValue containsCIS "Invoke-WebRequest" OR RegistryValue containsCIS "IWR " OR RegistryValue containsCIS " -noni " OR RegistryValue containsCIS " -noninteractive ") AND RegistryKeyPath containsCIS "\Software\Microsoft\Windows\CurrentVersion\Run"))

```