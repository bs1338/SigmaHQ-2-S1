# proc_creation_win_findstr_recon_pipe_output

## Title
Recon Command Output Piped To Findstr.EXE

## ID
ccb5742c-c248-4982-8c5c-5571b9275ad3

## Author
Nasreddine Bencherchali (Nextron Systems), frack113

## Date
2023-07-06

## Tags
attack.discovery, attack.t1057

## Description
Detects the execution of a potential recon command where the results are piped to "findstr". This is meant to trigger on inline calls of "cmd.exe" via the "/c" or "/k" for example.
Attackers often time use this technique to extract specific information they require in their reconnaissance phase.


## References
https://github.com/redcanaryco/atomic-red-team/blob/02cb591f75064ffe1e0df9ac3ed5972a2e491c97/atomics/T1057/T1057.md#atomic-test-6---discover-specific-process---tasklist
https://www.hhs.gov/sites/default/files/manage-engine-vulnerability-sector-alert-tlpclear.pdf
https://www.trendmicro.com/en_us/research/22/d/spring4shell-exploited-to-deploy-cryptocurrency-miners.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine = "*ipconfig*|*find*" OR TgtProcCmdLine = "*net*|*find*" OR TgtProcCmdLine = "*netstat*|*find*" OR TgtProcCmdLine = "*ping*|*find*" OR TgtProcCmdLine = "*systeminfo*|*find*" OR TgtProcCmdLine = "*tasklist*|*find*" OR TgtProcCmdLine = "*whoami*|*find*"))

```