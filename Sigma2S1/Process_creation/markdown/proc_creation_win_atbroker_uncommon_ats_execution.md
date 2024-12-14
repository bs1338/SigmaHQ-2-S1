# proc_creation_win_atbroker_uncommon_ats_execution

## Title
Uncommon  Assistive Technology Applications Execution Via AtBroker.EXE

## ID
f24bcaea-0cd1-11eb-adc1-0242ac120002

## Author
Mateusz Wydra, oscd.community

## Date
2020-10-12

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects the start of a non built-in assistive technology applications via "Atbroker.EXE".

## References
http://www.hexacorn.com/blog/2016/07/22/beyond-good-ol-run-key-part-42/
https://lolbas-project.github.io/lolbas/Binaries/Atbroker/

## False Positives
Legitimate, non-default assistive technology applications execution

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "start" AND TgtProcImagePath endswithCIS "\AtBroker.exe") AND (NOT (TgtProcCmdLine containsCIS "animations" OR TgtProcCmdLine containsCIS "audiodescription" OR TgtProcCmdLine containsCIS "caretbrowsing" OR TgtProcCmdLine containsCIS "caretwidth" OR TgtProcCmdLine containsCIS "colorfiltering" OR TgtProcCmdLine containsCIS "cursorindicator" OR TgtProcCmdLine containsCIS "cursorscheme" OR TgtProcCmdLine containsCIS "filterkeys" OR TgtProcCmdLine containsCIS "focusborderheight" OR TgtProcCmdLine containsCIS "focusborderwidth" OR TgtProcCmdLine containsCIS "highcontrast" OR TgtProcCmdLine containsCIS "keyboardcues" OR TgtProcCmdLine containsCIS "keyboardpref" OR TgtProcCmdLine containsCIS "livecaptions" OR TgtProcCmdLine containsCIS "magnifierpane" OR TgtProcCmdLine containsCIS "messageduration" OR TgtProcCmdLine containsCIS "minimumhitradius" OR TgtProcCmdLine containsCIS "mousekeys" OR TgtProcCmdLine containsCIS "Narrator" OR TgtProcCmdLine containsCIS "osk" OR TgtProcCmdLine containsCIS "overlappedcontent" OR TgtProcCmdLine containsCIS "showsounds" OR TgtProcCmdLine containsCIS "soundsentry" OR TgtProcCmdLine containsCIS "speechreco" OR TgtProcCmdLine containsCIS "stickykeys" OR TgtProcCmdLine containsCIS "togglekeys" OR TgtProcCmdLine containsCIS "voiceaccess" OR TgtProcCmdLine containsCIS "windowarranging" OR TgtProcCmdLine containsCIS "windowtracking" OR TgtProcCmdLine containsCIS "windowtrackingtimeout" OR TgtProcCmdLine containsCIS "windowtrackingzorder")) AND (NOT TgtProcCmdLine containsCIS "Oracle_JavaAccessBridge")))

```