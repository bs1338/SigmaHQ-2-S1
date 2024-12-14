# proc_creation_win_powershell_base64_hidden_flag

## Title
Malicious Base64 Encoded PowerShell Keywords in Command Lines

## ID
f26c6093-6f14-4b12-800f-0fcb46f5ffd0

## Author
John Lambert (rule)

## Date
2019-01-16

## Tags
attack.execution, attack.t1059.001

## Description
Detects base64 encoded strings used in hidden malicious PowerShell command lines

## References
http://www.leeholmes.com/blog/2017/09/21/searching-for-content-in-base-64-strings/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "AGkAdABzAGEAZABtAGkAbgAgAC8AdAByAGEAbgBzAGYAZQByA" OR TgtProcCmdLine containsCIS "aXRzYWRtaW4gL3RyYW5zZmVy" OR TgtProcCmdLine containsCIS "IAaQB0AHMAYQBkAG0AaQBuACAALwB0AHIAYQBuAHMAZgBlAHIA" OR TgtProcCmdLine containsCIS "JpdHNhZG1pbiAvdHJhbnNmZX" OR TgtProcCmdLine containsCIS "YgBpAHQAcwBhAGQAbQBpAG4AIAAvAHQAcgBhAG4AcwBmAGUAcg" OR TgtProcCmdLine containsCIS "Yml0c2FkbWluIC90cmFuc2Zlc" OR TgtProcCmdLine containsCIS "AGMAaAB1AG4AawBfAHMAaQB6AGUA" OR TgtProcCmdLine containsCIS "JABjAGgAdQBuAGsAXwBzAGkAegBlA" OR TgtProcCmdLine containsCIS "JGNodW5rX3Npem" OR TgtProcCmdLine containsCIS "QAYwBoAHUAbgBrAF8AcwBpAHoAZQ" OR TgtProcCmdLine containsCIS "RjaHVua19zaXpl" OR TgtProcCmdLine containsCIS "Y2h1bmtfc2l6Z" OR TgtProcCmdLine containsCIS "AE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4A" OR TgtProcCmdLine containsCIS "kATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8Abg" OR TgtProcCmdLine containsCIS "lPLkNvbXByZXNzaW9u" OR TgtProcCmdLine containsCIS "SQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuA" OR TgtProcCmdLine containsCIS "SU8uQ29tcHJlc3Npb2" OR TgtProcCmdLine containsCIS "Ty5Db21wcmVzc2lvb" OR TgtProcCmdLine containsCIS "AE8ALgBNAGUAbQBvAHIAeQBTAHQAcgBlAGEAbQ" OR TgtProcCmdLine containsCIS "kATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtA" OR TgtProcCmdLine containsCIS "lPLk1lbW9yeVN0cmVhb" OR TgtProcCmdLine containsCIS "SQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0A" OR TgtProcCmdLine containsCIS "SU8uTWVtb3J5U3RyZWFt" OR TgtProcCmdLine containsCIS "Ty5NZW1vcnlTdHJlYW" OR TgtProcCmdLine containsCIS "4ARwBlAHQAQwBoAHUAbgBrA" OR TgtProcCmdLine containsCIS "5HZXRDaHVua" OR TgtProcCmdLine containsCIS "AEcAZQB0AEMAaAB1AG4Aaw" OR TgtProcCmdLine containsCIS "LgBHAGUAdABDAGgAdQBuAGsA" OR TgtProcCmdLine containsCIS "LkdldENodW5r" OR TgtProcCmdLine containsCIS "R2V0Q2h1bm" OR TgtProcCmdLine containsCIS "AEgAUgBFAEEARABfAEkATgBGAE8ANgA0A" OR TgtProcCmdLine containsCIS "QASABSAEUAQQBEAF8ASQBOAEYATwA2ADQA" OR TgtProcCmdLine containsCIS "RIUkVBRF9JTkZPNj" OR TgtProcCmdLine containsCIS "SFJFQURfSU5GTzY0" OR TgtProcCmdLine containsCIS "VABIAFIARQBBAEQAXwBJAE4ARgBPADYANA" OR TgtProcCmdLine containsCIS "VEhSRUFEX0lORk82N" OR TgtProcCmdLine containsCIS "AHIAZQBhAHQAZQBSAGUAbQBvAHQAZQBUAGgAcgBlAGEAZA" OR TgtProcCmdLine containsCIS "cmVhdGVSZW1vdGVUaHJlYW" OR TgtProcCmdLine containsCIS "MAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkA" OR TgtProcCmdLine containsCIS "NyZWF0ZVJlbW90ZVRocmVhZ" OR TgtProcCmdLine containsCIS "Q3JlYXRlUmVtb3RlVGhyZWFk" OR TgtProcCmdLine containsCIS "QwByAGUAYQB0AGUAUgBlAG0AbwB0AGUAVABoAHIAZQBhAGQA" OR TgtProcCmdLine containsCIS "0AZQBtAG0AbwB2AGUA" OR TgtProcCmdLine containsCIS "1lbW1vdm" OR TgtProcCmdLine containsCIS "AGUAbQBtAG8AdgBlA" OR TgtProcCmdLine containsCIS "bQBlAG0AbQBvAHYAZQ" OR TgtProcCmdLine containsCIS "bWVtbW92Z" OR TgtProcCmdLine containsCIS "ZW1tb3Zl") AND TgtProcCmdLine containsCIS " hidden " AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe")))

```