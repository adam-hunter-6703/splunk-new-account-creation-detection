# splunk-new-account-creation-detection
Splunk detection for newly created Windows accounts using EventCode 4720. MITRE ATT&amp;CK T1098 aligned. Includes SPL, alert configuration, triage workflow, and screenshot.

# Splunk Detection: New Account Creation (EventCode 4720)

## Overview
This project demonstrates a Splunk detection engineered to identify newly created user accounts within a Windows environment. The alert leverages Windows Security EventCode **4720**, which indicates that a new local user account has been created. This detection aligns with **MITRE ATT&CK T1098 – Account Manipulation**, a technique commonly used by adversaries to establish persistence or escalate privileges.

This lab was completed as part of my SOC Analyst training through MYDFIR Forge.

##screenshots:
<img width="1884" height="1031" alt="New Account Alert" src="https://github.com/user-attachments/assets/e2ecf024-9eac-4014-85aa-d70b3f1c87c1" />



## 🔍 Detection Logic

### SPL Query
```spl
index=mydfir-lab1 EventCode=4720
