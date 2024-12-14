# registry_set_asep_reg_keys_modification_wow6432node_classes

## Title
Wow6432Node Classes Autorun Keys Modification

## ID
18f2065c-d36c-464a-a748-bcf909acb2e3

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
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath containsCIS "\Software\Wow6432Node\Classes" AND (RegistryKeyPath containsCIS "\Folder\ShellEx\ExtShellFolderViews" OR RegistryKeyPath containsCIS "\Folder\ShellEx\DragDropHandlers" OR RegistryKeyPath containsCIS "\Folder\ShellEx\ColumnHandlers" OR RegistryKeyPath containsCIS "\Directory\Shellex\DragDropHandlers" OR RegistryKeyPath containsCIS "\Directory\Shellex\CopyHookHandlers" OR RegistryKeyPath containsCIS "\CLSID\{AC757296-3522-4E11-9862-C17BE5A1767E}\Instance" OR RegistryKeyPath containsCIS "\CLSID\{ABE3B9A4-257D-4B97-BD1A-294AF496222E}\Instance" OR RegistryKeyPath containsCIS "\CLSID\{7ED96837-96F0-4812-B211-F13C24117ED3}\Instance" OR RegistryKeyPath containsCIS "\CLSID\{083863F1-70DE-11d0-BD40-00A0C911CE86}\Instance" OR RegistryKeyPath containsCIS "\AllFileSystemObjects\ShellEx\DragDropHandlers" OR RegistryKeyPath containsCIS "\ShellEx\PropertySheetHandlers" OR RegistryKeyPath containsCIS "\ShellEx\ContextMenuHandlers") AND (NOT RegistryValue = "(Empty)")))

```