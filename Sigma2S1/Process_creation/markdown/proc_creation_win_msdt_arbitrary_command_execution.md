# proc_creation_win_msdt_arbitrary_command_execution

## Title
Potential Arbitrary Command Execution Using Msdt.EXE

## ID
258fc8ce-8352-443a-9120-8a11e4857fa5

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-05-29

## Tags
attack.defense-evasion, attack.t1202

## Description
Detects processes leveraging the "ms-msdt" handler or the "msdt.exe" binary to execute arbitrary commands as seen in the follina (CVE-2022-30190) vulnerability

## References
https://twitter.com/nao_sec/status/1530196847679401984
https://app.any.run/tasks/713f05d2-fe78-4b9d-a744-f7c133e3fafb/
https://twitter.com/_JohnHammond/status/1531672601067675648

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\msdt.exe" AND (TgtProcCmdLine containsCIS "IT_BrowseForFile=" OR (TgtProcCmdLine containsCIS " PCWDiagnostic" AND (TgtProcCmdLine containsCIS " -af " OR TgtProcCmdLine containsCIS " /af " OR TgtProcCmdLine containsCIS " â€“af " OR TgtProcCmdLine containsCIS " â€”af " OR TgtProcCmdLine containsCIS " â€•af ")))))

```