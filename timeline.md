# Investigation Timeline

## Lab 56 – Suspicious Process Investigation

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

# Detailed Timeline

## 1. Wazuh Agent Verification

The Wazuh agent was verified using:

```bash
sudo /var/ossec/bin/agent_control -i 001
```

Observed:

```text
Agent ID:    001
Agent Name:  DESKTOP-9MMM37V
Status:      Active
```

### Assessment

Endpoint monitoring was established.

---

## 2. Endpoint Identification

Hostname:

```text
DESKTOP-9MMM37V
```

User:

```text
desktop-9mmm37v\dell
```

Baseline time:

```text
20 August 2026 10:05:10
```

### Assessment

The investigation host and user context were established.

---

## 3. PowerShell Path Validation

PowerShell was located at:

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

### Assessment

The executable was located in the expected Windows PowerShell directory.

---

## 4. Test Script Creation

Script:

```text
C:\Users\Public\Lab56-Test.ps1
```

Creation time:

```text
20-08-2026 10:11:27
```

Last write time:

```text
20-08-2026 10:11:27
```

### Assessment

The script was a controlled laboratory artifact.

---

## 5. Script Access

Last access time:

```text
20-08-2026 10:12:24
```

### Assessment

The access time was consistent with the laboratory activity.

---

## 6. Suspicious-Looking PowerShell Execution

The script was executed with:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Users\Public\Lab56-Test.ps1"
```

Output:

```text
Suspicious Process Investigation Lab 56
Host: DESKTOP-9MMM37V
User: desktop-9mmm37v\dell
```

### Assessment

The command line contained suspicious characteristics and required investigation.

---

## 7. CMD Child Process

The following command was executed:

```powershell
Start-Process cmd.exe
```

Controlled process relationship:

```text
powershell.exe
    |
    +-- cmd.exe
```

### Assessment

The child process was intentionally created as part of the laboratory.

---

## 8. CMD Follow-On Activity

The following commands were executed:

```cmd
whoami
hostname
ipconfig
```

### Assessment

The commands were harmless and were used to generate additional process activity.

---

## 9. Sysmon Event ID 1

Observed:

```text
Event ID:
1

Image:
C:\WINDOWS\System32\cmd.exe

Process ID:
31504

UtcTime:
2026-08-20 05:25:07.823
```

### Assessment

Sysmon confirmed `cmd.exe` process creation.

The displayed evidence does not contain the complete raw PowerShell Event ID 1 record.

---

## 10. File Metadata Review

Observed:

```text
Path:
C:\Users\Public\Lab56-Test.ps1

Length:
120 bytes

Creation:
20-08-2026 10:11:27

Last Write:
20-08-2026 10:11:27

Last Access:
20-08-2026 10:12:24
```

### Assessment

The file metadata was consistent with the controlled laboratory activity.

---

## 11. SHA256 Collection

SHA256:

```text
CE7240E3719B2FF154A4BA73333FDCE2A9B6E51759C8EBBFE24F6EA232046C4
```

### Assessment

The hash identifies the laboratory script.

---

## 12. PowerShell Signature Validation

PowerShell executable:

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

Signature status:

```text
Valid
```

Status message:

```text
Signature verified.
```

### Assessment

The PowerShell executable had a valid Authenticode signature.

---

## 13. Wazuh Correlation

Endpoint:

```text
agent.name: DESKTOP-9MMM37V
```

PowerShell:

```text
agent.name: DESKTOP-9MMM37V AND powershell.exe
```

CMD:

```text
agent.name: DESKTOP-9MMM37V AND cmd.exe
```

Test script:

```text
agent.name: DESKTOP-9MMM37V AND Lab56-Test.ps1
```

Execution policy:

```text
agent.name: DESKTOP-9MMM37V AND ExecutionPolicy
```

### Assessment

Wazuh was used to correlate the endpoint activity centrally.

---

# Suspicious Indicator Chain

```text
PowerShell
    |
    +-- -NoProfile
    |
    +-- -ExecutionPolicy Bypass
    |
    +-- C:\Users\Public\Lab56-Test.ps1
    |
    +-- cmd.exe
```

These characteristics justified investigation.

They do not independently prove malicious activity.

---

# Benign Context Chain

```text
Controlled Lab Activity
        |
        v
Harmless Script
        |
        v
Expected PowerShell Path
        |
        v
Valid Authenticode Signature
        |
        v
Known Script Hash
        |
        v
Intentional CMD Child Process
        |
        v
Harmless Commands
        |
        v
Benign Disposition
```

---

# Evidence Flow

```text
Wazuh Agent Verification
        |
        v
Endpoint Identification
        |
        v
PowerShell Path Validation
        |
        v
Script Creation
        |
        v
PowerShell Execution
        |
        v
Child Process Creation
        |
        v
Sysmon Event ID 1
        |
        v
Security Event ID 4688
        |
        v
File Metadata
        |
        v
SHA256
        |
        v
Signature Validation
        |
        v
Wazuh Correlation
        |
        v
Context Analysis
        |
        v
Final Disposition
```

---

# Evidence Limitations

The supplied screenshots do not contain complete raw process-creation telemetry for every process involved in the controlled execution.

The Sysmon evidence directly confirms `cmd.exe` process creation.

The PowerShell execution is demonstrated through the controlled PowerShell command and output.

Therefore, the timeline distinguishes between directly observed telemetry and the known controlled laboratory execution flow.

---

# Final Assessment

The activity contained several indicators that would reasonably trigger a SOC investigation:

- PowerShell execution
- `ExecutionPolicy Bypass`
- Script stored in `C:\Users\Public`
- CMD child-process activity

However, the investigation established strong benign context:

- Controlled laboratory activity
- Harmless script
- Expected PowerShell executable path
- Valid Authenticode signature
- Known script hash
- Intentional CMD process
- Harmless follow-on commands

---

# Final Disposition

**Benign / Controlled Suspicious-Process Simulation**

The investigation demonstrates that suspicious indicators should be validated through evidence correlation rather than treated as automatic proof of compromise.

The investigation flow was:

```text
Suspicious Activity
        |
        v
Validate
        |
        v
Investigate
        |
        v
Correlate
        |
        v
Understand Context
        |
        v
Make a Defensible Disposition
```
