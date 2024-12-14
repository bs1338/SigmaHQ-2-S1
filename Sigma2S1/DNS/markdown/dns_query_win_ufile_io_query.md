# dns_query_win_ufile_io_query

## Title
DNS Query To Ufile.io

## ID
1cbbeaaf-3c8c-4e4c-9d72-49485b6a176b

## Author
yatinwad, TheDFIRReport

## Date
2022-06-23

## Tags
attack.exfiltration, attack.t1567.002

## Description
Detects DNS queries to "ufile.io", which was seen abused by malware and threat actors as a method for data exfiltration

## References
https://thedfirreport.com/2021/12/13/diavol-ransomware/

## False Positives
DNS queries for "ufile" are not malicious by nature necessarily. Investigate the source to determine the necessary actions to take

## SentinelOne Query
```
ObjectType = "DNS" AND (EndpointOS = "windows" AND DnsRequest containsCIS "ufile.io")

```