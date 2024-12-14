# dns_query_win_regsvr32_dns_query

## Title
DNS Query Request By Regsvr32.EXE

## ID
36e037c4-c228-4866-b6a3-48eb292b9955

## Author
Dmitriy Lifanov, oscd.community

## Date
2019-10-25

## Tags
attack.execution, attack.t1559.001, attack.defense-evasion, attack.t1218.010

## Description
Detects DNS queries initiated by "Regsvr32.exe"

## References
https://pentestlab.blog/2017/05/11/applocker-bypass-regsvr32/
https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "DNS" AND (EndpointOS = "windows" AND SrcProcImagePath endswithCIS "\regsvr32.exe")

```