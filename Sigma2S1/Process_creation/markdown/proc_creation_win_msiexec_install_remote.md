# proc_creation_win_msiexec_install_remote

## Title
Suspicious Msiexec Quiet Install From Remote Location

## ID
8150732a-0c9d-4a99-82b9-9efb9b90c40c

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-10-28

## Tags
attack.defense-evasion, attack.t1218.007

## Description
Detects usage of Msiexec.exe to install packages hosted remotely quietly

## References
https://www.microsoft.com/en-us/security/blog/2022/10/27/raspberry-robin-worm-part-of-larger-ecosystem-facilitating-pre-ransomware-activity/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "-i" OR TgtProcCmdLine containsCIS "/i" OR TgtProcCmdLine containsCIS "â€“i" OR TgtProcCmdLine containsCIS "â€”i" OR TgtProcCmdLine containsCIS "â€•i" OR TgtProcCmdLine containsCIS "-package" OR TgtProcCmdLine containsCIS "/package" OR TgtProcCmdLine containsCIS "â€“package" OR TgtProcCmdLine containsCIS "â€”package" OR TgtProcCmdLine containsCIS "â€•package" OR TgtProcCmdLine containsCIS "-a" OR TgtProcCmdLine containsCIS "/a" OR TgtProcCmdLine containsCIS "â€“a" OR TgtProcCmdLine containsCIS "â€”a" OR TgtProcCmdLine containsCIS "â€•a" OR TgtProcCmdLine containsCIS "-j" OR TgtProcCmdLine containsCIS "/j" OR TgtProcCmdLine containsCIS "â€“j" OR TgtProcCmdLine containsCIS "â€”j" OR TgtProcCmdLine containsCIS "â€•j") AND TgtProcImagePath endswithCIS "\msiexec.exe" AND (TgtProcCmdLine containsCIS "-q" OR TgtProcCmdLine containsCIS "/q" OR TgtProcCmdLine containsCIS "â€“q" OR TgtProcCmdLine containsCIS "â€”q" OR TgtProcCmdLine containsCIS "â€•q") AND (TgtProcCmdLine containsCIS "http" OR TgtProcCmdLine containsCIS "\\")))

```