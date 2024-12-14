# proc_creation_win_susp_hidden_dir_index_allocation

## Title
Potential Hidden Directory Creation Via NTFS INDEX_ALLOCATION Stream - CLI

## ID
0900463c-b33b-49a8-be1d-552a3b553dae

## Author
Nasreddine Bencherchali (Nextron Systems), Scoubi (@ScoubiMtl)

## Date
2023-10-09

## Tags
attack.defense-evasion, attack.t1564.004

## Description
Detects command line containing reference to the "::$index_allocation" stream, which can be used as a technique to prevent access to folders or files from tooling such as "explorer.exe" or "powershell.exe"


## References
https://twitter.com/pfiatde/status/1681977680688738305
https://soroush.me/blog/2010/12/a-dotty-salty-directory-a-secret-place-in-ntfs-for-secret-files/
https://sec-consult.com/blog/detail/pentesters-windows-ntfs-tricks-collection/
https://github.com/redcanaryco/atomic-red-team/blob/5c3b23002d2bbede3c07e7307165fc2a235a427d/atomics/T1564.004/T1564.004.md#atomic-test-5---create-hidden-directory-via-index_allocation
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c54dec26-1551-4d3a-a0ea-4fa40f848eb3

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcCmdLine containsCIS "::$index_allocation")

```