# proc_creation_win_hktl_mimikatz_command_line

## Title
HackTool - Mimikatz Execution

## ID
a642964e-bead-4bed-8910-1bb4d63e3b4d

## Author
Teymur Kheirkhabarov, oscd.community, David ANDRE (additional keywords), Tim Shelton

## Date
2019-10-22

## Tags
attack.credential-access, attack.t1003.001, attack.t1003.002, attack.t1003.004, attack.t1003.005, attack.t1003.006

## Description
Detection well-known mimikatz command line arguments

## References
https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
https://tools.thehacker.recipes/mimikatz/modules

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "::aadcookie" OR TgtProcCmdLine containsCIS "::detours" OR TgtProcCmdLine containsCIS "::memssp" OR TgtProcCmdLine containsCIS "::mflt" OR TgtProcCmdLine containsCIS "::ncroutemon" OR TgtProcCmdLine containsCIS "::ngcsign" OR TgtProcCmdLine containsCIS "::printnightmare" OR TgtProcCmdLine containsCIS "::skeleton" OR TgtProcCmdLine containsCIS "::preshutdown" OR TgtProcCmdLine containsCIS "::mstsc" OR TgtProcCmdLine containsCIS "::multirdp") OR (TgtProcCmdLine containsCIS "rpc::" OR TgtProcCmdLine containsCIS "token::" OR TgtProcCmdLine containsCIS "crypto::" OR TgtProcCmdLine containsCIS "dpapi::" OR TgtProcCmdLine containsCIS "sekurlsa::" OR TgtProcCmdLine containsCIS "kerberos::" OR TgtProcCmdLine containsCIS "lsadump::" OR TgtProcCmdLine containsCIS "privilege::" OR TgtProcCmdLine containsCIS "process::" OR TgtProcCmdLine containsCIS "vault::") OR (TgtProcCmdLine containsCIS "DumpCreds" OR TgtProcCmdLine containsCIS "mimikatz")))

```