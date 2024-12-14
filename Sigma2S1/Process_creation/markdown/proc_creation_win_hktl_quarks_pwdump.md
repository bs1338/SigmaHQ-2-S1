# proc_creation_win_hktl_quarks_pwdump

## Title
HackTool - Quarks PwDump Execution

## ID
0685b176-c816-4837-8e7b-1216f346636b

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-09-05

## Tags
attack.credential-access, attack.t1003.002

## Description
Detects usage of the Quarks PwDump tool via commandline arguments

## References
https://github.com/quarkslab/quarkspwdump
https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/seedworm-apt-iran-middle-east

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine In Contains AnyCase (" -dhl"," --dump-hash-local"," -dhdc"," --dump-hash-domain-cached"," --dump-bitlocker"," -dhd "," --dump-hash-domain ","--ntds-file")) OR TgtProcImagePath endswithCIS "\QuarksPwDump.exe"))

```