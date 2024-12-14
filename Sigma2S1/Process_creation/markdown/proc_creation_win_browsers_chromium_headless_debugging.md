# proc_creation_win_browsers_chromium_headless_debugging

## Title
Potential Data Stealing Via Chromium Headless Debugging

## ID
3e8207c5-fcd2-4ea6-9418-15d45b4890e4

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-12-23

## Tags
attack.credential-access, attack.t1185

## Description
Detects chromium based browsers starting in headless and debugging mode and pointing to a user profile. This could be a sign of data stealing or remote control

## References
https://github.com/defaultnamehere/cookie_crimes/
https://mango.pdf.zone/stealing-chrome-cookies-without-a-password
https://embracethered.com/blog/posts/2020/cookie-crimes-on-mirosoft-edge/
https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "--remote-debugging-" AND TgtProcCmdLine containsCIS "--user-data-dir" AND TgtProcCmdLine containsCIS "--headless"))

```