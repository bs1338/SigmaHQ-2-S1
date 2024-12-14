# file_event_win_susp_right_to_left_override_extension_spoofing

## Title
Potential File Extension Spoofing Using Right-to-Left Override

## ID
979baf41-ca44-4540-9d0c-4fcef3b5a3a4

## Author
Jonathan Peters (Nextron Systems), Florian Roth (Nextron Systems)

## Date
2024-11-17

## Tags
attack.execution, attack.defense-evasion, attack.t1036.002

## Description
Detects suspicious filenames that contain a right-to-left override character and a potentially spoofed file extensions.


## References
https://redcanary.com/blog/right-to-left-override/
https://www.malwarebytes.com/blog/news/2014/01/the-rtlo-method

## False Positives
Filenames that contains scriptures such as arabic or hebrew might make use of this character

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath containsCIS "fpd.." OR TgtFilePath containsCIS "nls.." OR TgtFilePath containsCIS "vsc.." OR TgtFilePath containsCIS "xcod." OR TgtFilePath containsCIS "xslx.") AND TgtFilePath containsCIS "\u202e"))

```