# proc_creation_win_python_inline_command_execution

## Title
Python Inline Command Execution

## ID
899133d5-4d7c-4a7f-94ee-27355c879d90

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-01-02

## Tags
attack.execution, attack.t1059

## Description
Detects execution of python using the "-c" flag. This is could be used as a way to launch a reverse shell or execute live python code.

## References
https://docs.python.org/3/using/cmdline.html#cmdoption-c
https://www.revshells.com/
https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

## False Positives
Python libraries that use a flag starting with "-c". Filter according to your environment

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -c" AND (TgtProcImagePath endswithCIS "python.exe" OR TgtProcImagePath endswithCIS "python3.exe" OR TgtProcImagePath endswithCIS "python2.exe")) AND (NOT ((SrcProcCmdLine containsCIS "-E -s -m ensurepip -U --default-pip" AND SrcProcImagePath endswithCIS "\python.exe" AND SrcProcImagePath startswithCIS "C:\Program Files\Python") OR SrcProcImagePath endswithCIS "\AppData\Local\Programs\Microsoft VS Code\Code.exe"))))

```