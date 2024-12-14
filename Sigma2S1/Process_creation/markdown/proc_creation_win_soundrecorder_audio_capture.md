# proc_creation_win_soundrecorder_audio_capture

## Title
Audio Capture via SoundRecorder

## ID
83865853-59aa-449e-9600-74b9d89a6d6e

## Author
E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community

## Date
2019-10-24

## Tags
attack.collection, attack.t1123

## Description
Detect attacker collecting audio via SoundRecorder application.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1123/T1123.md
https://eqllib.readthedocs.io/en/latest/analytics/f72a98cb-7b3d-4100-99c3-a138b6e9ff6e.html

## False Positives
Legitimate audio capture by legitimate user.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "/FILE" AND TgtProcImagePath endswithCIS "\SoundRecorder.exe"))

```