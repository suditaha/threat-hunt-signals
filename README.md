<p align="center">
<img src="images/banner.png" width="100%">
</p>

# Signal Before The Noise 2 - Threat Hunt Investigation

## Scenario

A suspicious login was detected inside the PHTG environment. Initial assumptions suggested brute-force activity, but telemetry quickly revealed a more sophisticated intrusion involving:

- Valid account abuse
- Lateral movement
- PowerShell execution
- Persistence mechanisms
- Defender tampering
- LOLBin masquerading
- Beaconing activity
- AMSI reconnaissance
- LSASS credential access

The objective was to reconstruct the operator's activity on `azwks-phtg-01` and identify the full attack chain from initial access through credential dumping.

---

# Skills Demonstrated

- Microsoft Defender XDR
- Kusto Query Language (KQL)
- Threat Hunting
- MITRE ATT&CK Mapping
- Persistence Analysis
- Registry Forensics
- Process Lineage Analysis
- Beacon Detection
- Windows Event Analysis
- Credential Access Detection

---

# MITRE ATT&CK Techniques Observed

| Technique | Description |
|------------|------------|
| T1078 | Valid Accounts |
| T1021 | Remote Services |
| T1059.001 | PowerShell |
| T1547.001 | Registry Run Keys |
| T1547.009 | Shortcut Modification |
| T1112 | Modify Registry |
| T1562.001 | Defender Evasion |
| T1036 | Masquerading |
| T1105 | Ingress Tool Transfer |
| T1071 | Application Layer Protocol |
| T1003.001 | LSASS Memory Access |

---

# Investigation Timeline

---

## Phase 1 — Initial Access

### Finding

No brute force indicators were present.

Successful authentication occurred using a previously valid credential.

### Conclusion

Initial access was achieved through:

```text
Password Reuse
```

MITRE:

```text
T1078 - Valid Accounts
```

---

## Phase 2 — Lateral Movement

### Evidence

Account:

```text
vmadminusername
```

Source:

```text
10.0.0.152
```

Target:

```text
azwks-phtg-01
```

Logon Type:

```text
RemoteInteractive
```

Time:

```text
09:48:40 UTC
```

### KQL

```kql
DeviceLogonEvents
| where Timestamp >= datetime(2025-12-13 09:48:00)
| where DeviceName == "azwks-phtg-01"
| project Timestamp, AccountName, RemoteIP, LogonType
```

### Conclusion

Operator successfully moved laterally onto:

```text
azwks-phtg-01
```

---

## Phase 3 — PowerShell Execution

### First Operator Script

```text
C:\Users\vmAdminUsername\Documents\PHTG\_.ps1
```

### Execution Flags

```powershell
-WindowStyle Hidden
-ExecutionPolicy Bypass
```

### Significance

These flags indicate an attempt to:

- Hide execution
- Bypass local PowerShell restrictions

MITRE:

```text
T1059.001 - PowerShell
```

---

## Phase 4 — Operator Workspace

### Root Staging Directory

```text
C:\ProgramData\PHTG\HealthCloud
```

### Subdirectories

```text
Cache
Bin
TempCache
```

### Concealment Activity

| Directory | Hidden Operations |
|------------|------------|
| Cache | 17 |
| TempCache | 2 |

Most concealment activity occurred in:

```text
Cache
```

---

## Phase 5 — LOLBin Masquerading

### Suspicious Binary

```text
PHTGHealthCloudSvc.exe
```

Claimed Original Filename:

```text
bitsadmin.exe
```

Location:

```text
C:\ProgramData\PHTG\HealthCloud
```

### Why Suspicious?

Legitimate LOLBins execute from Windows system paths.

This binary executed from an attacker-controlled workspace.

MITRE:

```text
T1036 - Masquerading
```

---

## Phase 6 — Persistence

### Registry Run Key

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

### Value Name

```text
PHTGHealthCloudTray
```

### Startup Command

```powershell
powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\PHTG\HealthCloud\Bin\HealthCloudTray.ps1"
```

---

### Startup Folder Persistence

Artifact:

```text
PHTG HealthCloud.lnk
```

Location:

```text
Startup Folder
```

MITRE:

```text
T1547.001
T1547.009
```

---

## Phase 7 — Custom Event Log Source

### Registry Key

```text
HKLM\SYSTEM\ControlSet001\Services\EventLog\Application\PHTGHealthCloud
```

### Purpose

Allowed tooling to:

- Write custom Application log events
- Blend activity into legitimate Windows logging

---

## Phase 8 — Beaconing Activity

### Domains

```text
status.health-cloud.cc
updates.health-cloud.cc
```

### Endpoints

```text
/api/checkin
/api/status
```

### Decoded PowerShell Beacons

```text
https://status.health-cloud.cc/api/checkin
https://status.health-cloud.cc/api/status
```

### Healthcheck Loop

Observed:

```text
22 executions
```

of:

```text
/healthcheck
```

---

## Phase 9 — AMSI Reconnaissance

### Script

```text
amsi_probe.ps1
```

### Purpose

Determine whether:

```text
AMSI inspection was active
```

before executing additional payloads.

MITRE:

```text
T1562
```

---

## Phase 10 — Defender Tampering

### Path Exclusion

```text
C:\ProgramData\PHTG\HealthCloud\Cache
```

### Process Exclusion

```text
C:\ProgramData\PHTG\HealthCloud\PHTGHealthCloudSvc.exe
```

### Additional Temporary Exclusion

```text
C:\Users\vmAdminUsername\Documents\PHTG
```

### Purpose

Reduce Defender visibility during staging and execution.

MITRE:

```text
T1562.001
```

---

## Phase 11 — Process Lineage Evasion

### Payloads

```text
hc_lineage.ps1
```

```text
phtg_health_diag_update_FLAG-22.bat
```

### Launch Method

```cmd
cmd.exe /c
```

### Purpose

Break parent-child process relationships and complicate detection.

---

## Phase 12 — Credential Access

### Suspicious LSASS Access

Account:

```text
vmadminusername
```

Process:

```text
powershell.exe
```

### OpenProcess Access Masks

Initial:

```text
5136
```

Escalated:

```text
2047999
```

### Significance

PowerShell first obtained limited access before escalating to near full access against LSASS.

---

### Credential Dump Confirmation

Observed:

```text
ReadProcessMemoryApiCall
```

This confirms memory was read after the LSASS handle was opened.

MITRE:

```text
T1003.001 - LSASS Memory
```

---

# Final Assessment

The operator successfully:

1. Authenticated using a reused credential
2. Moved laterally to azwks-phtg-01
3. Executed hidden PowerShell tooling
4. Established multiple persistence mechanisms
5. Added Defender exclusions
6. Masqueraded tooling as a LOLBin
7. Created custom event logging
8. Established outbound beaconing
9. Performed AMSI reconnaissance
10. Accessed LSASS memory for credential harvesting

The attack progressed from valid account abuse to credential dumping with multiple layers of persistence and defense evasion in between.

---

# Key Detection Opportunities

- Hidden PowerShell execution
- Defender exclusion creation
- Registry Run key modifications
- Startup folder persistence
- LOLBin filename mismatch
- AMSI reconnaissance scripts
- Custom event log source creation
- LSASS OpenProcess access escalation
- ReadProcessMemory activity

---

# Tools Used

- Microsoft Defender XDR
- Advanced Hunting
- Kusto Query Language (KQL)
- MITRE ATT&CK Framework
