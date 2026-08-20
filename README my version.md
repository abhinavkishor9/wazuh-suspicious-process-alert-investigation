# wazuh-suspicious-process-alert-investigation
## Overview

A suspicious process alert occurs when a process exhibits characteristics that are unusual for the endpoint, user, or normal operating baseline.

The process itself may be completely legitimate.

For example:

powershell.exe
cmd.exe
rundll32.exe
wscript.exe
mshta.exe

are legitimate Windows binaries, but their execution context can make them suspicious.

The SOC investigation therefore asks:

What process?
     ↓
Who started it?
     ↓
What was the command line?
     ↓
What was the parent process?
     ↓
Where did it execute from?
     ↓
What happened afterward?
     ↓
Was the behavior expected?
Example

A normal event:

explorer.exe
    ↓
powershell.exe
    ↓
Get-Service

may simply represent normal administration.

A more suspicious chain:

winword.exe
    ↓
powershell.exe
    ↓
Encoded / unusual command
    ↓
cmd.exe

requires investigation.

The key lesson is:

A suspicious process is not necessarily a malicious process. Context determines the risk.



This lab investigates suspicious-looking PowerShell and Windows command-shell activity on a Windows 11 endpoint monitored by Wazuh.

The investigation was performed using a controlled and harmless PowerShell script created at:

`C:\Users\Public\Lab56-Test.ps1`

The script was executed using PowerShell with `-NoProfile` and `-ExecutionPolicy Bypass`, followed by the intentional creation of a `cmd.exe` child process.

The investigation focuses on determining whether the observed process activity should be considered malicious or benign by correlating endpoint activity, process information, file metadata, hashing, Authenticode signature validation, Sysmon telemetry, Windows Security process-creation events, and Wazuh data.

The lab demonstrates an important SOC principle:

> A suspicious process or command line is an investigation trigger, not automatically a confirmation of malicious activity.

---

## Lab Objectives

- Investigate suspicious-looking PowerShell execution.
- Identify the affected host and user.
- Validate the PowerShell executable path.
- Examine the PowerShell command line.
- Investigate `-ExecutionPolicy Bypass`.
- Investigate a script stored in `C:\Users\Public`.
- Examine process activity involving `powershell.exe` and `cmd.exe`.
- Review Sysmon Event ID 1.
- Review Windows Security Event ID 4688.
- Examine file metadata.
- Calculate the SHA256 hash of the test script.
- Validate the PowerShell executable's Authenticode signature.
- Correlate endpoint activity with Wazuh.
- Reconstruct the investigation timeline.
- Determine an evidence-based final disposition.
- Document evidence limitations.

---

## Lab Environment

| Component | Value |
|---|---|
| Operating System | Windows 11 Pro |
| Wazuh Version | 4.12.0 |
| Wazuh Agent ID | 001 |
| Hostname | DESKTOP-9MMM37V |
| User | desktop-9mmm37v\dell |
| Primary Interpreter | Windows PowerShell |
| Child Process | cmd.exe |
| Test Script | C:\Users\Public\Lab56-Test.ps1 |
| Sysmon Event | Event ID 1 |
| Windows Security Event | Event ID 4688 |

---

## Tools Used

- Wazuh
- Windows Event Viewer
- Sysmon
- PowerShell
- Windows Command Prompt
- `Get-Process`
- `Get-Command`
- `Get-Item`
- `Get-FileHash`
- `Get-AuthenticodeSignature`
- `hostname`
- `whoami`
- `ipconfig`

---

# Investigation Scenario

A Windows workstation generates process activity involving PowerShell.

The PowerShell command contains:

```text
-NoProfile
-ExecutionPolicy Bypass
-File C:\Users\Public\Lab56-Test.ps1
```

A `cmd.exe` process is also launched from PowerShell.

From a SOC perspective, these characteristics deserve investigation because PowerShell execution with `ExecutionPolicy Bypass`, scripts stored in user-accessible locations, and command-shell activity can be associated with suspicious execution.

However, these indicators alone do not establish malicious activity.

The investigation therefore focuses on correlating the process, user, command line, file, process creation events, and endpoint telemetry before reaching a final disposition.

---

# Investigation Workflow

```text
Wazuh Verification
        |
        v
Endpoint Identification
        |
        v
PowerShell Path Validation
        |
        v
Controlled Script Creation
        |
        v
PowerShell Execution
        |
        v
Child Process Creation
        |
        v
Process Investigation
        |
        v
Sysmon Event ID 1
        |
        v
Windows Security Event ID 4688
        |
        v
File Metadata and Hash
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

# Investigation

## 1. Verify Wazuh Agent

The Wazuh agent was checked from the Wazuh server using:

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

The endpoint was actively connected to Wazuh.

---

## 2. Identify the Endpoint

The endpoint was identified using:

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
20 August 2026
```

---

## 3. Validate PowerShell Path

The PowerShell executable location was checked using:

```powershell
Get-Command powershell.exe |
Select-Object Source
```

Observed:

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

This is the expected Windows PowerShell executable path.

---

## 4. Create the Test Script

A harmless PowerShell script was created at:

```text
C:\Users\Public\Lab56-Test.ps1
```

The script contained:

```powershell
Write-Output "Suspicious Process Investigation Lab 56"
Write-Output "Host: $(hostname)"
Write-Output "User: $(whoami)"
```

The script was verified with:

```powershell
Get-Content "C:\Users\Public\Lab56-Test.ps1"
```

The script contained no malicious payload.

---

## 5. Execute the Script

The script was executed using:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Users\Public\Lab56-Test.ps1"
```

Observed output:

```text
Suspicious Process Investigation Lab 56
Host: DESKTOP-9MMM37V
User: desktop-9mmm37v\dell
```

The command line contained several investigation indicators:

```text
powershell.exe
-NoProfile
-ExecutionPolicy Bypass
C:\Users\Public\Lab56-Test.ps1
```

These characteristics justified further investigation.

---

## 6. Create a Child Process

A `cmd.exe` process was intentionally launched from PowerShell:

```powershell
Start-Process cmd.exe
```

The controlled process relationship was:

```text
powershell.exe
    |
    +-- cmd.exe
```

The CMD process was then used to execute:

```cmd
whoami
hostname
ipconfig
```

These commands were harmless and were generated for investigation and telemetry correlation.

---

# Process Investigation

## 7. Review CMD Processes

The local process list was checked using:

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

---

## 8. Review PowerShell Processes

PowerShell-related processes were checked using:

```powershell
Get-Process *powershell*, *pwsh* |
Select-Object Id, ProcessName, StartTime
```

Observed:

```text
Id      ProcessName    StartTime
22248   pwsh           20-08-2026 08:39:50
```

The local process listing did not provide the complete historical parent-child relationship.

For historical process-tree reconstruction, Sysmon Event ID 1 and Windows Security Event ID 4688 are more useful.

---

# Windows Event Investigation

## 9. Sysmon Event ID 1

Sysmon Operational logs were reviewed for Event ID 1.

The displayed event showed:

```text
Event ID:      1
Task Category: Process Create

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

The event confirms process creation for `cmd.exe`.

The supplied evidence does not contain a complete raw Sysmon Event ID 1 record for the original PowerShell execution.

Therefore, the investigation should not claim that all PowerShell process-tree fields were recovered directly from this event.

---

## 10. Windows Security Event ID 4688

Windows Security Event ID 4688 was identified as another process-creation evidence source.

Relevant fields to examine include:

- New Process Name
- Process ID
- Creator Process ID
- Command Line
- Subject User
- Timestamp

Event ID 4688 should be correlated with Sysmon Event ID 1 and Wazuh telemetry when available.

---

# File Investigation

## 11. File Metadata

The test script metadata was collected using:

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

The timestamps are consistent with the controlled laboratory activity.

---

## 12. Calculate SHA256

The script hash was collected using:

```powershell
Get-FileHash "C:\Users\Public\Lab56-Test.ps1" -Algorithm SHA256
```

SHA256:

```text
CE7240E3719B2FF154A4BA73333FDCE2A9B6E51759C8EBBFE24F6EA232046C4
```

The hash identifies the controlled laboratory artifact.

It should not be treated as a malicious IOC.

---

## 13. Validate PowerShell Signature

The PowerShell executable was checked using:

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

The PowerShell executable had a valid Authenticode signature.

A valid signature confirms the executable's signature status but does not make every PowerShell command benign.

---

# Wazuh Investigation

## 14. Endpoint Search

The endpoint can be identified in Wazuh using:

```text
agent.name: DESKTOP-9MMM37V
```

---

## 15. PowerShell Search

Search for PowerShell activity:

```text
agent.name: DESKTOP-9MMM37V AND powershell.exe
```

Search specifically for the test script:

```text
agent.name: DESKTOP-9MMM37V AND Lab56-Test.ps1
```

Search for execution-policy activity:

```text
agent.name: DESKTOP-9MMM37V AND ExecutionPolicy
```

---

## 16. CMD Search

Search for CMD activity:

```text
agent.name: DESKTOP-9MMM37V AND cmd.exe
```

The objective is to correlate the CMD process with the PowerShell execution.

---

# MITRE ATT&CK Context

## T1059.001 – Command and Scripting Interpreter: PowerShell

PowerShell was used to execute the test script.

The use of PowerShell with `ExecutionPolicy Bypass` represents a useful SOC detection and investigation condition.

## T1059.003 – Command and Scripting Interpreter: Windows Command Shell

`cmd.exe` was launched as a child process and used to execute harmless commands.

The activity was intentionally generated for this laboratory.

---
