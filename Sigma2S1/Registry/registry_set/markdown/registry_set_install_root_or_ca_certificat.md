# registry_set_install_root_or_ca_certificat

## Title
New Root or CA or AuthRoot Certificate to Store

## ID
d223b46b-5621-4037-88fe-fda32eead684

## Author
frack113

## Date
2022-04-04

## Tags
attack.impact, attack.t1490

## Description
Detects the addition of new root, CA or AuthRoot certificates to the Windows registry

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1553.004/T1553.004.md#atomic-test-6---add-root-certificate-to-currentuser-certificate-store
https://posts.specterops.io/code-signing-certificate-cloning-attacks-and-defenses-6f98657fc6ec

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "Binary Data" AND (RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates\" OR RegistryKeyPath containsCIS "\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates\" OR RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\EnterpriseCertificates\Root\Certificates\" OR RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\SystemCertificates\CA\Certificates\" OR RegistryKeyPath containsCIS "\SOFTWARE\Policies\Microsoft\SystemCertificates\CA\Certificates\" OR RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\EnterpriseCertificates\CA\Certificates\" OR RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates\" OR RegistryKeyPath containsCIS "\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot\Certificates\" OR RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\EnterpriseCertificates\AuthRoot\Certificates\") AND RegistryKeyPath endswithCIS "\Blob"))

```