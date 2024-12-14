# proc_creation_win_finger_execution

## Title
Finger.EXE Execution

## ID
af491bca-e752-4b44-9c86-df5680533dbc

## Author
Florian Roth (Nextron Systems), omkar72, oscd.community

## Date
2021-02-24

## Tags
attack.command-and-control, attack.t1105

## Description
Detects execution of the "finger.exe" utility.
Finger.EXE or "TCPIP Finger Command" is an old utility that is still present on modern Windows installation. It Displays information about users on a specified remote computer (typically a UNIX computer) that is running the finger service or daemon.
Due to the old nature of this utility and the rareness of machines having the finger service. Any execution of "finger.exe" can be considered "suspicious" and worth investigating.


## References
https://twitter.com/bigmacjpg/status/1349727699863011328?s=12
https://app.any.run/tasks/40115012-a919-4208-bfed-41e82cb3dadf/
http://hyp3rlinx.altervista.org/advisories/Windows_TCPIP_Finger_Command_C2_Channel_and_Bypassing_Security_Software.txt

## False Positives
Admin activity (unclear what they do nowadays with finger.exe)

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcImagePath endswithCIS "\finger.exe")

```