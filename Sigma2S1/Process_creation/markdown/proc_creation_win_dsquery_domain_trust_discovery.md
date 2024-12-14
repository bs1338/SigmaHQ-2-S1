# proc_creation_win_dsquery_domain_trust_discovery

## Title
Domain Trust Discovery Via Dsquery

## ID
3bad990e-4848-4a78-9530-b427d854aac0

## Author
E.M. Anhaus, Tony Lambert, oscd.community, omkar72

## Date
2019-10-24

## Tags
attack.discovery, attack.t1482

## Description
Detects execution of "dsquery.exe" for domain trust discovery

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1482/T1482.md
https://posts.specterops.io/an-introduction-to-manual-active-directory-querying-with-dsquery-and-ldapsearch-84943c13d7eb?gi=41b97a644843

## False Positives
Legitimate use of the utilities by legitimate user for legitimate reason

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "trustedDomain" AND TgtProcImagePath endswithCIS "\dsquery.exe"))

```