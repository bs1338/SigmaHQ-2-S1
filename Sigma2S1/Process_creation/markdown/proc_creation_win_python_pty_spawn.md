# proc_creation_win_python_pty_spawn

## Title
Python Spawning Pretty TTY on Windows

## ID
480e7e51-e797-47e3-8d72-ebfce65b6d8d

## Author
Nextron Systems

## Date
2022-06-03

## Tags
attack.execution, attack.t1059

## Description
Detects python spawning a pretty tty

## References
https://www.volexity.com/blog/2022/06/02/zero-day-exploitation-of-atlassian-confluence/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "python.exe" OR TgtProcImagePath endswithCIS "python3.exe" OR TgtProcImagePath endswithCIS "python2.exe") AND ((TgtProcCmdLine containsCIS "import pty" AND TgtProcCmdLine containsCIS ".spawn(") OR TgtProcCmdLine containsCIS "from pty import spawn")))

```