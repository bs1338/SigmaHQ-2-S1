# proc_creation_win_susp_right_to_left_override

## Title
Potential Defense Evasion Via Right-to-Left Override

## ID
ad691d92-15f2-4181-9aa4-723c74f9ddc3

## Author
Micah Babinski, @micahbabinski

## Date
2023-02-15

## Tags
attack.defense-evasion, attack.t1036.002

## Description
Detects the presence of the "u202+E" character, which causes a terminal, browser, or operating system to render text in a right-to-left sequence.
This is used as an obfuscation and masquerading techniques.


## References
https://redcanary.com/blog/right-to-left-override/
https://www.malwarebytes.com/blog/news/2014/01/the-rtlo-method
https://unicode-explorer.com/c/202E

## False Positives
Commandlines that contains scriptures such as arabic or hebrew might make use of this character

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcCmdLine containsCIS "â€®")

```