# proc_creation_win_dirlister_execution

## Title
DirLister Execution

## ID
b4dc61f5-6cce-468e-a608-b48b469feaa2

## Author
frack113

## Date
2022-08-20

## Tags
attack.discovery, attack.t1083

## Description
Detect the usage of "DirLister.exe" a utility for quickly listing folder or drive contents. It was seen used by BlackCat ransomware to create a list of accessible directories and files.

## References
https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1083/T1083.md
https://news.sophos.com/en-us/2022/07/14/blackcat-ransomware-attacks-not-merely-a-byproduct-of-bad-luck/

## False Positives
Legitimate use by users

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcImagePath endswithCIS "\dirlister.exe")

```