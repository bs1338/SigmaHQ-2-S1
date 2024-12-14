# registry_set_susp_keyboard_layout_load

## Title
Suspicious Keyboard Layout Load

## ID
34aa0252-6039-40ff-951f-939fd6ce47d8

## Author
Florian Roth (Nextron Systems)

## Date
2019-10-12

## Tags
attack.resource-development, attack.t1588.002

## Description
Detects the keyboard preload installation with a suspicious keyboard layout, e.g. Chinese, Iranian or Vietnamese layout load in user session on systems maintained by US staff only

## References
https://renenyffenegger.ch/notes/Windows/registry/tree/HKEY_CURRENT_USER/Keyboard-Layout/Preload/index
https://github.com/SwiftOnSecurity/sysmon-config/pull/92/files

## False Positives
Administrators or users that actually use the selected keyboard layouts (heavily depends on the organisation's user base)

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryValue containsCIS "00000429" OR RegistryValue containsCIS "00050429" OR RegistryValue containsCIS "0000042a") AND (RegistryKeyPath containsCIS "\Keyboard Layout\Preload\" OR RegistryKeyPath containsCIS "\Keyboard Layout\Substitutes\")))

```