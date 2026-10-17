# FYODOR-L Incident Investigation

## 1. Incident Overview

## 2. Initial Detection

## 3. Evidence Analysis
### Evidence 01 — Suspicious Encoded PowerShell Execution

**Evidence ID:** SOC-001-E01  
**Hostname:** FYODOR-L  
**SIEM Platform:** Splunk Enterprise  
**Dataset:** BOTS v3  
**Evidence Type:** Process command-line telemetry  
**Observed Date:** August 20, 2018  
**Observed Time Range:** 18:01:41–19:32:13 (Splunk-displayed time; timezone not verified)  
**Classification:** Suspicious PowerShell Activity  
**Investigation Status:** Requires Further Analysis

#### A. Evidence Description

Analysis of Splunk logs identified multiple PowerShell executions originating from the FYODOR-L endpoint.

Seven matching events are visible in the collected evidence. The observed commands contain execution parameters associated with encoded script execution, hidden windows, non-interactive operation, and references to Windows registry locations.

The repeated use of these parameters warrants further investigation into possible script obfuscation, unauthorized command execution, and registry-based activity.

#### B. Observed Command-Line Patterns

**Pattern 1 — Encoded PowerShell Execution**

```powershell
powershell.exe -noP -sta -w 1 -enc <Base64_payload>
```

Observed at:
- 2018-08-20 18:01:41
- 2018-08-20 18:01:44

**Pattern 2 — Hidden, Non-Interactive Encoded Execution**

```powershell
powershell.exe -NoP -NonI -W Hidden -enc <Base64_payload>
```

Observed at:
- 2018-08-20 18:07:06
- 2018-08-20 18:15:27
- 2018-08-20 19:32:13

**Pattern 3 — Hidden PowerShell with Registry References**

```powershell
powershell.exe -NoP -NonI -W Hidden -c $x=$(gp HKCU:Software\Microsoft...
```

Observed at:
- 2018-08-20 18:07:06
- 2018-08-20 19:32:12

The command lines shown above are abbreviated representations of the visible evidence. Complete payloads and registry paths were not available in the screenshot.

#### C. Technical Analysis

The observed PowerShell commands contain several security-relevant execution parameters:

| Parameter | Technical Interpretation |
|---|---|
| `-NoP` | Prevents loading the PowerShell profile |
| `-NonI` | Runs PowerShell without interactive prompts |
| `-W Hidden` | Requests hidden window execution |
| `-enc` | Executes a Base64-encoded command |
| `-sta` | Starts PowerShell in single-threaded apartment mode |
| `-c` | Executes the supplied command |

Encoded commands can conceal script content from casual inspection. Hidden execution can reduce user visibility, while non-interactive execution is commonly associated with automated scripts.

The observed registry references may indicate configuration retrieval, script loading, or other registry interactions. Their purpose cannot be established without the complete commands.

#### D. Security Assessment

**Observed Facts:**
- Seven PowerShell execution records are visible.
- Multiple commands use encoded payloads.
- Several commands request hidden execution.
- Two commands contain partially visible registry references.
- Similar execution patterns appear at different timestamps.

**Potential Security Implications:**
- Obfuscated script execution.
- Execution of unauthorized PowerShell commands.
- Possible registry-based script storage or retrieval.
- Potential association with other suspicious endpoint activity.

**Analytical Limitations:**
- The encoded payloads have not been decoded.
- Complete registry paths are unavailable.
- Parent processes and executing user accounts are not shown.
- No direct network connection or persistence mechanism is established by this screenshot.

**Analyst Assessment:**

The combination of encoded PowerShell execution, hidden window parameters, and registry references constitutes suspicious endpoint behavior.

The evidence supports further investigation into possible malicious script execution. However, the available screenshot is insufficient to confirm the payload's functionality, persistence, or successful compromise.

#### E. MITRE ATT&CK Mapping

| Technique | ID | Assessment |
|---|---|---|
| PowerShell | T1059.001 | Observed PowerShell execution |
| Obfuscated Files or Information | T1027 | Possible obfuscation; payload content not yet examined |

The use of `-enc` supports investigating obfuscation but does not independently establish malicious intent.

#### F. Recommended Investigation Actions

1. Extract the complete command-line values from Splunk.
2. Decode the Base64 payloads without executing them.
3. Examine the full registry commands.
4. Identify the parent processes and associated user accounts.
5. Correlate execution timestamps with subsequent account, persistence, firewall, and network activity.

#### G. Evidence Reference

![Suspicious PowerShell execution on FYODOR-L](https://github.com/ElleEspiritu/Splunk-SOC-Incident-Investigation/blob/f1e4bea8fa973839532635c15befa564019ae202/investigations/FYODOR-L-Incident/screenshots/01-encoded-powershell.png)


**Figure 1.** Splunk search results showing encoded PowerShell execution, hidden execution parameters, and registry references on FYODOR-L.

**Evidence Status:** Documented — Further Correlation Required.



### Evidence 02 — Suspicious Local Account Creation and Administrator Group Modification

**Evidence ID:** SOC-001-E02  
**Hostname:** FYODOR-L  
**SIEM Platform:** Splunk Enterprise  
**Dataset:** BOTS v3  
**Evidence Type:** Windows Process Command-Line Activity  
**Observed Date:** August 20, 2018  
**Observed Time Range:** 18:08:17–18:08:35 (Splunk-displayed time; timezone not verified)  
**Target Account:** `svcvmc`  
**Classification:** Suspicious Account Creation and Privilege Modification  
**Investigation Status:** High Priority — Requires Validation

#### A. Evidence Description

Analysis of Windows process execution telemetry in Splunk identified two commands associated with local account management on the FYODOR-L endpoint.

The first command attempted to create a new local user account named `svcvmc`. Approximately 18 seconds later, a second command attempted to add the same account to the local Administrators group.

The close temporal relationship and matching account name indicate a coordinated sequence of account creation and privilege assignment.

#### B. Observed Command-Line Activity

**Event 1 — Local User Account Creation**

**Timestamp:** 2018-08-20 18:08:17

```cmd
"C:\Windows\system32\net.exe" user /add svcvmc Password123!
```

**Technical Interpretation:**

The `net user /add` command requests the creation of a local Windows account.

The specified password is embedded directly in the command line, potentially exposing credentials to process logging and other monitoring mechanisms.

**Event 2 — Local Administrator Group Modification**

**Timestamp:** 2018-08-20 18:08:35

```cmd
"C:\Windows\system32\net.exe" localgroup administrators svcvmc /add
```

**Technical Interpretation:**

The `net localgroup administrators` command requests the addition of `svcvmc` to the local Administrators group.

If successful, the account would receive administrative group membership, potentially enabling elevated access to the endpoint.

#### C. Technical Analysis

The two observed commands form a suspicious account management sequence.

The first command attempts to establish a new local account. The second attempts to assign administrative privileges to that account.

This sequence is consistent with behavior that an attacker could use to establish an alternative privileged account for continued access.

However, command execution telemetry alone does not establish whether the commands completed successfully.

#### D. Security Assessment

**Observed Facts:**
- Two `net.exe` commands were observed on FYODOR-L.
- The first command attempted to create the local account `svcvmc`.
- The second command attempted to add `svcvmc` to the local Administrators group.
- Both commands targeted the same account.
- The commands were recorded 18 seconds apart.

**Potential Security Implications:**
- Unauthorized local account creation.
- Attempted acquisition of privileged account access.
- Potential establishment of an alternative access mechanism.
- Possible persistence through an attacker-controlled local account.

**Analytical Limitations:**
- Successful account creation has not been verified.
- Successful administrator group membership has not been verified.
- The executing user and parent process are not shown.
- The available evidence does not independently establish who initiated the commands.

**Analyst Assessment:**

The observed commands indicate a high-priority account management anomaly.

The attempted creation of a local user account followed by an attempt to assign administrator privileges is consistent with adversary techniques used to establish privileged access.

The activity is particularly concerning when considered alongside the earlier suspicious PowerShell execution on the same endpoint.

Further correlation is required to confirm whether the account was successfully created, elevated, and subsequently used.

#### E. MITRE ATT&CK Mapping

| Technique | ID | Evidence-Based Assessment |
|---|---|---|
| Create Account: Local Account | T1136.001 | Account creation command observed; success unverified |
| Account Manipulation: Additional Local or Domain Groups | T1098.007 | Attempt to add account to local Administrators group observed |

**Note:** These mappings describe observed attempted behaviors. Successful persistence or privilege escalation has not yet been confirmed.

#### F. Recommended Investigation Actions

1. Search for Windows Security Event ID 4720 to verify successful account creation.
2. Search for Event ID 4732 to verify local Administrators group membership changes.
3. Identify the user and parent process responsible for the commands.
4. Search for subsequent authentication events involving `svcvmc`.
5. Correlate these events with the PowerShell activity recorded earlier on FYODOR-L.

#### G. Evidence Reference

![Account creation and administrator group modification]([screenshots/02-account-creation.png](https://github.com/ElleEspiritu/Splunk-SOC-Incident-Investigation/blob/f1e4bea8fa973839532635c15befa564019ae202/investigations/FYODOR-L-Incident/screenshots/02-account-creation.png))

**Figure 2.** Splunk results showing `net.exe` commands attempting to create the `svcvmc` account and add it to the local Administrators group on FYODOR-L.

**Evidence Status:** Documented — Account Creation and Privilege Assignment Require Confirmation.



## 4. Incident Timeline

## 5. Findings

## 6. Conclusion
