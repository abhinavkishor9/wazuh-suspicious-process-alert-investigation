# Investigation Timeline
| Time | Activity | Evidence | Assessment |
|---|---|---|---|
| 08:39:50 | PowerShell 7 process observed | `Get-Process` | Existing `pwsh.exe` process |
| 10:05:10 | Endpoint baseline captured | PowerShell | Host, user, and time established |
| 10:11:27 | Test script created | File metadata | Controlled laboratory artifact |
| 10:11:27 | Script last modified | File metadata | Consistent with creation |
| 10:12:24 | Script last accessed | File metadata | Consistent with laboratory activity |
| 10:13:05 | CMD process observed | `Get-Process` | Process activity observed |
| Investigation window | PowerShell executed with `ExecutionPolicy Bypass` | PowerShell | Suspicious-looking execution |
| Investigation window | `cmd.exe` launched from PowerShell | PowerShell | Controlled child-process activity |
| Investigation window | `whoami`, `hostname`, `ipconfig` executed | CMD | Harmless follow-on activity |
| 10:55:07 | Sysmon Event ID 1 observed | Sysmon | `cmd.exe` process creation |
| Investigation window | File metadata reviewed | PowerShell | Artifact validation |
| Investigation window | SHA256 calculated | PowerShell | Artifact identification |
| Investigation window | PowerShell signature validated | Authenticode | Valid signed executable |
| Investigation window | Wazuh telemetry reviewed | Wazuh | Centralized correlation |
| Final | Evidence correlated | DFIR analysis | Controlled activity |
| Final | Analyst disposition | Investigation | Benign / Controlled Activity |

---

