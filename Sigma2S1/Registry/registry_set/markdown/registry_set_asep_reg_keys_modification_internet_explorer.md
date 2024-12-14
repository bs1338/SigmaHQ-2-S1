# registry_set_asep_reg_keys_modification_internet_explorer

## Title
Internet Explorer Autorun Keys Modification

## ID
a80f662f-022f-4429-9b8c-b1a41aaa6688

## Author
Victor Sergeev, Daniil Yugoslavskiy, Gleb Sukhodolskiy, Timur Zinniatullin, oscd.community, Tim Shelton, frack113 (split)

## Date
2019-10-25

## Tags
attack.persistence, attack.t1547.001

## Description
Detects modification of autostart extensibility point (ASEP) in registry.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.001/T1547.001.md
https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
https://gist.github.com/GlebSukhodolskiy/0fc5fa5f482903064b448890db1eaf9d

## False Positives
Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason
Legitimate administrator sets up autorun keys for legitimate reason

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath containsCIS "\Software\Wow6432Node\Microsoft\Internet Explorer" OR RegistryKeyPath containsCIS "\Software\Microsoft\Internet Explorer") AND (RegistryKeyPath containsCIS "\Toolbar" OR RegistryKeyPath containsCIS "\Extensions" OR RegistryKeyPath containsCIS "\Explorer Bars") AND (NOT (RegistryValue = "(Empty)" OR (RegistryKeyPath containsCIS "\Extensions\{2670000A-7350-4f3c-8081-5663EE0C6C49}" OR RegistryKeyPath containsCIS "\Extensions\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}" OR RegistryKeyPath containsCIS "\Extensions\{789FE86F-6FC4-46A1-9849-EDE0DB0C95CA}" OR RegistryKeyPath containsCIS "\Extensions\{A95fe080-8f5d-11d2-a20b-00aa003c157a}") OR (RegistryKeyPath endswithCIS "\Toolbar\ShellBrowser\ITBar7Layout" OR RegistryKeyPath endswithCIS "\Toolbar\ShowDiscussionButton" OR RegistryKeyPath endswithCIS "\Toolbar\Locked")))))

```