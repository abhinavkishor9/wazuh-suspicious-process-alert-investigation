# Investigation Notes

## Lab 56 – Suspicious Process Investigation

## 1. Investigation Overview

This investigation focused on suspicious-looking PowerShell and CMD activity on a Windows 11 endpoint monitored by Wazuh.

The activity was intentionally generated using a harmless PowerShell script. The investigation was performed to practice process investigation, command-line analysis, file analysis, Sysmon investigation, Windows Security event analysis, and Wazuh correlation.

The primary question was whether the suspicious-looking execution represented malicious activity or controlled laboratory activity.

---

## 2. Endpoint Details

| Field | Value |
|---|---|
| Hostname | DESKTOP-9MMM37V |
| User | desktop-9mmm37v\dell |
| Operating System | Windows 11 Pro |
| Wazuh Agent ID | 001 |
| Wazuh Version | 4.12.0 |
| Agent Status | Active |

---

## 3. Wazuh Agent Verification

Command:

```bash
sudo /var/ossec/bin/agent_control -i 001
```

Observed:

```text
Agent ID:    001
Agent Name:  DESKTOP-9MMM37V
IP address:  any
Status:      Active

Operating system:    Microsoft Windows 11 Pro
Client version:      Wazuh v4.12.0
```

### Assessment

The endpoint was actively connected to Wazuh.

---

## 4. Endpoint Identification

Commands:

```powershell
hostname
```

```powershell
whoami
```

```powershell
Get-Date
```

Observed:

```text
Hostname:
DESKTOP-9MMM37V

User:
desktop-9mmm37v\dell

Date:
20 August 2026 10:05:10
```

### Assessment

The endpoint and user context were established before investigating the process activity.

---

## 5. PowerShell Path Validation

Command:

```powershell
Get-Command powershell.exe |
Select-Object Source
```

Observed:

```text
Source
------
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

### Assessment

The executable was located in the expected Windows PowerShell directory.

---

## 6. Test Script

The test script was created at:

```text
C:\Users\Public\Lab56-Test.ps1
```

Contents:

```powershell
Write-Output "Suspicious Process Investigation Lab 56"
Write-Output "Host: $(hostname)"
Write-Output "User: $(whoami)"
```

The contents were verified using:

```powershell
Get-Content "C:\Users\Public\Lab56-Test.ps1"
```

### Assessment

The script was intentionally harmless and did not contain a malicious payload.

---

## 7. Suspicious-Looking PowerShell Command

The script was executed using:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Users\Public\Lab56-Test.ps1"
```

Output:

```text
Suspicious Process Investigation Lab 56
Host: DESKTOP-9MMM37V
User: desktop-9mmm37v\dell
```

### Suspicious Indicators

```text
-NoProfile
-ExecutionPolicy Bypass
C:\Users\Public\Lab56-Test.ps1
```

### Assessment

The command line was suspicious enough to justify investigation.

However, the command line alone does not establish malicious execution.

---

## 8. Child Process

Command:

```powershell
Start-Process cmd.exe
```

Controlled process relationship:

```text
powershell.exe
    |
    +-- cmd.exe
```

The CMD process was then used for:

```cmd
whoami
hostname
ipconfig
```

### Assessment

The child process activity was intentionally generated for the investigation.

---

## 9. Process Enumeration

Command:

```powershell
Get-Process cmd |
Select-Object Id, ProcessName, StartTime
```

Observed:

```text
Id      ProcessName    StartTime
11912   cmd            19-08-2026 14:29:52
12116   cmd            19-08-2026 14:29:52
28236   cmd            20-08-2026 10:13:05
```

PowerShell-related processes:

```powershell
Get-Process *powershell*, *pwsh* |
Select-Object Id, ProcessName, StartTime
```

Observed:

```text
Id      ProcessName    StartTime
22248   pwsh           20-08-2026 08:39:50
```

### Assessment

The local process listing provided process information but did not provide a complete historical process tree.

---

## 10. Sysmon Event ID 1

The Sysmon Operational log showed:

```text
Event ID:      1
Task Category: Process Create
```

Observed process:

```text
Image:
C:\WINDOWS\System32\cmd.exe

Process ID:
31504

FileVersion:
10.0.22621.6133

Description:
Windows Command Processor

Product:
Microsoft® Windows® Operating System

UtcTime:
2026-08-20 05:25:07.823
```

### Assessment

The event confirms `cmd.exe` process creation.

The supplied evidence does not contain the complete raw Sysmon Event ID 1 record for the original PowerShell execution.

This limitation should be explicitly documented.

---

## 11. Windows Security Event ID 4688

Windows Security Event ID 4688 was identified as an additional process-creation telemetry source.

Important fields for correlation include:

- New Process Name
- Process ID
- Creator Process ID
- Command Line
- Subject User
- Timestamp

### Assessment

Security Event 4688 should be correlated with Sysmon Event ID 1 and Wazuh telemetry when available.

---

## 12. File Metadata

Command:

```powershell
Get-Item "C:\Users\Public\Lab56-Test.ps1" |
Select-Object FullName, Length, CreationTime, LastWriteTime, LastAccessTime
```

Observed:

```text
FullName:
C:\Users\Public\Lab56-Test.ps1

Length:
120

CreationTime:
20-08-2026 10:11:27

LastWriteTime:
20-08-2026 10:11:27

LastAccessTime:
20-08-2026 10:12:24
```

### Assessment

The timestamps are consistent with the controlled laboratory activity.

---

## 13. File Hash

Command:

```powershell
Get-FileHash "C:\Users\Public\Lab56-Test.ps1" -Algorithm SHA256
```

SHA256:

```text
CE7240E3719B2FF154A4BA73333FDCE2A9B6E51759C8EBBFE24F6EA232046C4
```

### Assessment

The hash identifies the laboratory test artifact.

It should not be treated as a malicious IOC.

---

## 14. PowerShell Signature

Command:

```powershell
Get-AuthenticodeSignature "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
```

Observed:

```text
Status:
Valid

StatusMessage:
Signature verified.
```

### Assessment

The PowerShell executable had a valid Authenticode signature.

This confirms the signature status of the executable but does not automatically make all PowerShell activity benign.

---

## 15. Wazuh Searches

Endpoint:

```text
agent.name: DESKTOP-9MMM37V
```

PowerShell:

```text
agent.name: DESKTOP-9MMM37V AND powershell.exe
```

Script:

```text
agent.name: DESKTOP-9MMM37V AND Lab56-Test.ps1
```

Execution policy:

```text
agent.name: DESKTOP-9MMM37V AND ExecutionPolicy
```

CMD:

```text
agent.name: DESKTOP-9MMM37V AND cmd.exe
```

### Assessment

Wazuh provides centralized endpoint telemetry for correlation.

---

## 16. Evidence Correlation

| Evidence | Finding | Significance |
|---|---|---|
| Wazuh | Agent 001 active | Endpoint visibility |
| Host | DESKTOP-9MMM37V | Host attribution |
| User | desktop-9mmm37v\dell | User attribution |
| PowerShell path | Expected Windows path | Normal executable location |
| Signature | Valid | Signed executable |
| Script location | C:\Users\Public | Suspicious context |
| Execution policy | Bypass | Suspicious indicator |
| Script contents | Harmless | Benign context |
| File metadata | Consistent with lab activity | Benign context |
| SHA256 | Recorded | Artifact identification |
| CMD | Child process | Process context |
| Sysmon Event 1 | cmd.exe creation | Process telemetry |
| Security Event 4688 | Process creation source | Correlation source |
| Wazuh | Endpoint telemetry | Centralized correlation |

---

## 17. Analyst Assessment

The following characteristics required investigation:

```text
PowerShell
+
ExecutionPolicy Bypass
+
C:\Users\Public
+
cmd.exe
```

However, the investigation also established:

```text
Controlled laboratory activity
+
Harmless script
+
Expected PowerShell path
+
Valid PowerShell signature
+
Known script hash
+
Intentional CMD process
+
Harmless commands
```

The available evidence does not establish malicious execution.

---

## 18. Final Disposition

**Benign / Controlled Activity**

The observed activity was intentionally generated as part of Lab 56.

The activity was suspicious enough to investigate, but the available evidence supports a benign laboratory disposition.

---

## 19. Evidence Limitations

The supplied screenshots do not provide complete raw process-creation telemetry for every process in the intended execution chain.

The Sysmon screenshot directly confirms `cmd.exe` process creation.

The PowerShell execution is demonstrated through the controlled PowerShell command and its output.

Therefore, the investigation should distinguish between directly observed telemetry and the known laboratory execution flow.

---

## 20. Final Analyst Statement

> The PowerShell activity was suspicious enough to investigate because it used `ExecutionPolicy Bypass`, executed a script from `C:\Users\Public`, and was followed by `cmd.exe` activity. Correlation with the controlled script contents, file metadata, SHA256 hash, valid PowerShell signature, and known laboratory activity supports a final disposition of benign controlled activity.
