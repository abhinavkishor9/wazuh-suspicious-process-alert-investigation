# Troubleshooting Notes
---

## 1. PowerShell 7 vs Windows PowerShell

### Observation

The process enumeration returned:

```text
Id      ProcessName    StartTime
22248   pwsh           20-08-2026 08:39:50
```

However, the investigation used:

```text
powershell.exe
```

### Explanation

`pwsh.exe` represents PowerShell 7, while:

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

represents Windows PowerShell.

These are different PowerShell executables.

### Recommended Check

Use:

```powershell
Get-Command powershell.exe |
Select-Object Source
```

and:

```powershell
Get-Command pwsh.exe |
Select-Object Source
```

When investigating PowerShell activity, record the full executable path rather than relying only on the process name.

---

## 2. Get-Process Does Not Reconstruct a Historical Process Tree

### Observation

The following command:

```powershell
Get-Process cmd |
Select-Object Id, ProcessName, StartTime
```

provides currently running process information.

It does not provide a complete historical parent-child relationship.

### Resolution

Use process-creation telemetry such as:

```text
Sysmon Event ID 1
```

and:

```text
Windows Security Event ID 4688
```

Important fields include:

- Process ID
- Parent Process ID
- Image
- Parent Image
- Command Line
- User
- Timestamp

---

## 3. Sysmon Event 1 Evidence Limitation

### Observation

The supplied Sysmon event shows:

```text
Image:
C:\WINDOWS\System32\cmd.exe
```

### Limitation

The supplied evidence does not contain the complete raw Sysmon Event ID 1 record for the original PowerShell execution.

### Resolution

Do not claim that the complete PowerShell process tree was recovered from Sysmon.

Document the evidence as:

```text
Directly observed:
cmd.exe Sysmon Event ID 1
```

and separately:

```text
Controlled laboratory execution:
powershell.exe -> cmd.exe
```

---

## 4. Large Sysmon Event Volume

### Observation

The Sysmon Operational log displayed approximately:

```text
54,745 events
```

### Problem

A broad search can produce a large amount of unrelated process activity.

### Resolution

First narrow the investigation to the endpoint:

```text
agent.name: DESKTOP-9MMM37V
```

Then search for:

```text
agent.name: DESKTOP-9MMM37V AND powershell.exe
```

```text
agent.name: DESKTOP-9MMM37V AND cmd.exe
```

```text
agent.name: DESKTOP-9MMM37V AND Lab56-Test.ps1
```

```text
agent.name: DESKTOP-9MMM37V AND ExecutionPolicy
```

Use a narrow time range around the laboratory activity.

---

## 5. ExecutionPolicy Bypass

### Observation

The PowerShell command contained:

```text
-ExecutionPolicy Bypass
```

### Explanation

`ExecutionPolicy Bypass` is a useful detection indicator because PowerShell execution policies can be bypassed during malicious activity.

However, the presence of this parameter alone does not prove malicious execution.

### Recommended Investigation

Correlate it with:

- User
- Parent process
- Child process
- Command line
- Script path
- Script contents
- File metadata
- File hash
- Process path
- Signature
- Wazuh telemetry

---

## 6. C:\Users\Public

### Observation

The script was stored at:

```text
C:\Users\Public\Lab56-Test.ps1
```

### Explanation

The location deserves investigation because it is a user-accessible directory.

However, the location itself is not proof of malicious activity.

### Recommended Checks

```powershell
Get-Item "C:\Users\Public\Lab56-Test.ps1"
```

```powershell
Get-Content "C:\Users\Public\Lab56-Test.ps1"
```

```powershell
Get-FileHash "C:\Users\Public\Lab56-Test.ps1" -Algorithm SHA256
```

---

## 7. Authenticode Signature

### Observation

The PowerShell executable returned:

```text
Status:
Valid

StatusMessage:
Signature verified.
```

### Interpretation

The executable had a valid Authenticode signature.

### Important Limitation

A valid signature does not prove that the command executed through PowerShell is benign.

Correct interpretation:

```text
The PowerShell executable has a valid signature.
```

Incorrect interpretation:

```text
All PowerShell activity is legitimate.
```

---

## 8. Wazuh Agent Verification

The Wazuh agent was checked using:

```bash
sudo /var/ossec/bin/agent_control -i 001
```

Expected status:

```text
Agent ID:    001
Agent Name:  DESKTOP-9MMM37V
Status:      Active
```

If the agent is not active, check the Wazuh agent service and connectivity.

For example:

```bash
sudo systemctl status wazuh-agent
```

Also verify:

- Wazuh agent service
- Manager connectivity
- Agent configuration
- Windows event collection
- Endpoint connectivity
- System time
- Wazuh search time range

---

## 9. UTC vs Local Time

Sysmon records UTC timestamps.

Example:

```text
UtcTime:
2026-08-20 05:25:07.823
```

The Event Viewer timestamp was:

```text
20-08-2026 10:55:07
```

The Windows host is using India Standard Time.

When correlating events, always identify the timezone before comparing timestamps.

---

## 10. Windows Security Event 4688

Event ID 4688 represents process creation.

If the event is not available, verify Windows process-creation auditing.

Relevant fields include:

- New Process Name
- Process ID
- Creator Process ID
- Command Line
- Subject User
- Timestamp

If 4688 is unavailable, use Sysmon Event ID 1 and other available telemetry.

Do not invent missing event fields.

---

## 11. Wazuh Field Availability

Wazuh may expose endpoint telemetry differently from Event Viewer.

Start with:

```text
agent.name: DESKTOP-9MMM37V
```

Then narrow the search:

```text
agent.name: DESKTOP-9MMM37V AND powershell.exe
```

```text
agent.name: DESKTOP-9MMM37V AND cmd.exe
```

```text
agent.name: DESKTOP-9MMM37V AND Lab56-Test.ps1
```

If a specific field is not available in Wazuh, use Event Viewer as the direct Windows evidence source and Wazuh for centralized correlation.

---

## 12. Evidence Limitations

The available screenshots do not contain complete raw process-creation records for every process involved in the controlled execution.

The investigation should clearly distinguish:

```text
Directly observed evidence
```

from:

```text
Known controlled laboratory activity
```

This prevents overstatement of the forensic findings.

---

## 13. Cleanup

After completing the lab, remove the test script:

```powershell
Remove-Item "C:\Users\Public\Lab56-Test.ps1" -Force
```

Verify removal:

```powershell
Test-Path "C:\Users\Public\Lab56-Test.ps1"
```

Expected result:

```text
False
```

Close any CMD or PowerShell processes created specifically for the laboratory.

---

