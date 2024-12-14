# proc_creation_win_susp_private_keys_recon

## Title
Private Keys Reconnaissance Via CommandLine Tools

## ID
213d6a77-3d55-4ce8-ba74-fcfef741974e

## Author
frack113, Nasreddine Bencherchali (Nextron Systems)

## Date
2021-07-20

## Tags
attack.credential-access, attack.t1552.004

## Description
Adversaries may search for private key certificate files on compromised systems for insecurely stored credential

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1552.004/T1552.004.md

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS ".key" OR TgtProcCmdLine containsCIS ".pgp" OR TgtProcCmdLine containsCIS ".gpg" OR TgtProcCmdLine containsCIS ".ppk" OR TgtProcCmdLine containsCIS ".p12" OR TgtProcCmdLine containsCIS ".pem" OR TgtProcCmdLine containsCIS ".pfx" OR TgtProcCmdLine containsCIS ".cer" OR TgtProcCmdLine containsCIS ".p7b" OR TgtProcCmdLine containsCIS ".asc") AND ((TgtProcCmdLine containsCIS "dir " AND TgtProcImagePath endswithCIS "\cmd.exe") OR (TgtProcCmdLine containsCIS "Get-ChildItem " AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe")) OR TgtProcImagePath endswithCIS "\findstr.exe")))

```