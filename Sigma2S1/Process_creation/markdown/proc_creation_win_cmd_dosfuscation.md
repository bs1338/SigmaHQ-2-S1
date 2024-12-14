# proc_creation_win_cmd_dosfuscation

## Title
Potential Dosfuscation Activity

## ID
a77c1610-fc73-4019-8e29-0f51efc04a51

## Author
frack113, Nasreddine Bencherchali (Nextron Systems)

## Date
2022-02-15

## Tags
attack.execution, attack.t1059

## Description
Detects possible payload obfuscation via the commandline

## References
https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/dosfuscation-report.pdf
https://github.com/danielbohannon/Invoke-DOSfuscation

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "^^" OR TgtProcCmdLine containsCIS "^|^" OR TgtProcCmdLine containsCIS ",;," OR TgtProcCmdLine containsCIS ";;;;" OR TgtProcCmdLine containsCIS ";; ;;" OR TgtProcCmdLine containsCIS "(,(," OR TgtProcCmdLine containsCIS "%COMSPEC:~" OR TgtProcCmdLine containsCIS " c^m^d" OR TgtProcCmdLine containsCIS "^c^m^d" OR TgtProcCmdLine containsCIS " c^md" OR TgtProcCmdLine containsCIS " cm^d" OR TgtProcCmdLine containsCIS "^cm^d" OR TgtProcCmdLine containsCIS " s^et " OR TgtProcCmdLine containsCIS " s^e^t " OR TgtProcCmdLine containsCIS " se^t "))

```