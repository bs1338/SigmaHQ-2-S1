# proc_creation_win_powershell_export_certificate

## Title
Certificate Exported Via PowerShell

## ID
9e716b33-63b2-46da-86a4-bd3c3b9b5dfb

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-18

## Tags
attack.credential-access, attack.execution, attack.t1552.004, attack.t1059.001

## Description
Detects calls to cmdlets that are used to export certificates from the local certificate store. Threat actors were seen abusing this to steal private keys from compromised machines.

## References
https://us-cert.cisa.gov/ncas/analysis-reports/ar21-112a
https://learn.microsoft.com/en-us/powershell/module/pki/export-pfxcertificate?view=windowsserver2022-ps
https://www.splunk.com/en_us/blog/security/breaking-the-chain-defending-against-certificate-services-abuse.html

## False Positives
Legitimate certificate exports by administrators. Additional filters might be required.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "Export-PfxCertificate " OR TgtProcCmdLine containsCIS "Export-Certificate "))

```