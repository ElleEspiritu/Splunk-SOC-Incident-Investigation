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

![Suspicious PowerShell execution on FYODOR-L](investigations/FYODOR-L-Incident/screenshots)

**Figure 1.** Splunk search results showing encoded PowerShell execution, hidden execution parameters, and registry references on FYODOR-L.

**Evidence Status:** Documented — Further Correlation Required.

## 4. Incident Timeline

## 5. Findings

## 6. Conclusion
