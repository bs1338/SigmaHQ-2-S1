# proc_creation_win_browsers_tor_execution

## Title
Tor Client/Browser Execution

## ID
62f7c9bf-9135-49b2-8aeb-1e54a6ecc13c

## Author
frack113

## Date
2022-02-20

## Tags
attack.command-and-control, attack.t1090.003

## Description
Detects the use of Tor or Tor-Browser to connect to onion routing networks

## References
https://www.logpoint.com/en/blog/detecting-tor-use-with-logpoint/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\tor.exe" OR TgtProcImagePath endswithCIS "\Tor Browser\Browser\firefox.exe"))

```