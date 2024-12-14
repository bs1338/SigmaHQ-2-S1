# file_event_win_susp_dpapi_backup_and_cert_export_ioc

## Title
DPAPI Backup Keys And Certificate Export Activity IOC

## ID
7892ec59-c5bb-496d-8968-e5d210ca3ac4

## Author
Nounou Mbeiri, Nasreddine Bencherchali (Nextron Systems)

## Date
2024-06-26

## Tags
attack.t1555, attack.t1552.004

## Description
Detects file names with specific patterns seen generated and used by tools such as Mimikatz and DSInternals related to exported or stolen DPAPI backup keys and certificates.


## References
https://www.dsinternals.com/en/dpapi-backup-key-theft-auditing/
https://github.com/MichaelGrafnetter/DSInternals/blob/39ee8a69bbdc1cfd12c9afdd7513b4788c4895d4/Src/DSInternals.Common/Data/DPAPI/DPAPIBackupKey.cs#L28-L32

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath containsCIS "ntds_capi_" OR TgtFilePath containsCIS "ntds_legacy_" OR TgtFilePath containsCIS "ntds_unknown_") AND (TgtFilePath endswithCIS ".cer" OR TgtFilePath endswithCIS ".key" OR TgtFilePath endswithCIS ".pfx" OR TgtFilePath endswithCIS ".pvk")))

```