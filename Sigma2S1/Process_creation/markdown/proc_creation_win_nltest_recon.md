# proc_creation_win_nltest_recon

## Title
Potential Recon Activity Via Nltest.EXE

## ID
5cc90652-4cbd-4241-aa3b-4b462fa5a248

## Author
Craig Young, oscd.community, Georg Lauenstein

## Date
2021-07-24

## Tags
attack.discovery, attack.t1016, attack.t1482

## Description
Detects nltest commands that can be used for information discovery

## References
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935(v=ws.11)
https://thedfirreport.com/2021/08/16/trickbot-leads-up-to-fake-1password-installation/
https://thedfirreport.com/2020/10/18/ryuk-in-5-hours/
https://book.hacktricks.xyz/windows/basic-cmd-for-pentesters
https://research.nccgroup.com/2022/08/19/back-in-black-unlocking-a-lockbit-3-0-ransomware-attack/
https://eqllib.readthedocs.io/en/latest/analytics/03e231a6-74bc-467a-acb1-e5676b0fb55e.html
https://redcanary.com/blog/how-one-hospital-thwarted-a-ryuk-ransomware-outbreak/
https://github.com/redcanaryco/atomic-red-team/blob/5360c9d9ffa3b25f6495f7a16e267b719eba2c37/atomics/T1482/T1482.md#atomic-test-2---windows---discover-domain-trusts-with-nltest

## False Positives
Legitimate administration use but user and host must be investigated

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\nltest.exe" AND ((TgtProcCmdLine containsCIS "server" AND TgtProcCmdLine containsCIS "query") OR (TgtProcCmdLine containsCIS "/user" OR TgtProcCmdLine containsCIS "all_trusts" OR TgtProcCmdLine containsCIS "dclist:" OR TgtProcCmdLine containsCIS "dnsgetdc:" OR TgtProcCmdLine containsCIS "domain_trusts" OR TgtProcCmdLine containsCIS "dsgetdc:" OR TgtProcCmdLine containsCIS "parentdomain" OR TgtProcCmdLine containsCIS "trusted_domains"))))

```