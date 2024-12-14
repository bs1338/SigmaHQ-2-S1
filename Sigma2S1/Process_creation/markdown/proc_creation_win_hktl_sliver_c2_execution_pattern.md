# proc_creation_win_hktl_sliver_c2_execution_pattern

## Title
HackTool - Sliver C2 Implant Activity Pattern

## ID
42333b2c-b425-441c-b70e-99404a17170f

## Author
Nasreddine Bencherchali (Nextron Systems), Florian Roth (Nextron Systems)

## Date
2022-08-25

## Tags
attack.execution, attack.t1059

## Description
Detects process activity patterns as seen being used by Sliver C2 framework implants

## References
https://github.com/BishopFox/sliver/blob/79f2d48fcdfc2bee4713b78d431ea4b27f733f30/implant/sliver/shell/shell_windows.go#L36
https://www.microsoft.com/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcCmdLine containsCIS "-NoExit -Command [Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8")

```