# Lab 01: Real-Time File Integrity Monitoring (FIM) & Telemetry Validation

## Executive Summary
This project showcases my first deployment of custom File Integrity Monitoring (FIM) rules in `/var/ossec/etc/ossec.conf`. 

The motivation for building this detection capability came from a security incident while playing *Call of Duty: Black Ops II* (outside of the Plutonium client framework). During a match, an adversary pushed a dynamic pop-up message to my screen claiming local system compromise. While likely an in-game engine exploit or prank, the encounter highlighted a critical visibility gap: I lacked the host-based logging and monitoring rules required to investigate post-exploitation actions, persistence mechanisms, or unauthorized file modifications.

This lab demonstrates the practical deployment and validation of host-based FIM using a local Wazuh SIEM architecture. The goal was to observe host-based detection mechanisms in real-time, inspect raw JSON log telemetry, and verify detection engine alignment with standard cybersecurity frameworks (MITRE ATT&CK, NIST 800-53).

---

## Lab Architecture Overveiw
* **SIEM Manager:** `192.168.1.30` (`Wazuh-Manager-01`)
* **Monitored Endpoint:** `192.168.1.40` (`Endpoint-Linux-01 / Debian Linux`)
* **Detection Mechanism:** Wazuh `syscheckd` engine utilizing Linux kernel `inotify` triggers

---

## 1.Confiuration & Baseline Verification

### 1. Configuration
Configured the target endpoint agent to monitor sensitive SSH user configuration files in real time with change reporting enabled:

```xml
<syscheck>
  <directories realtime="yes" report_changes="yes">/home/labuser/.ssh</directories>
</syscheck>
```
### 2.Baseline Scan Verification
Monitored initial system scanning telementary via ``/var/ossec/logs/ossec.log`` to confirm syscheckd completed it's baseline build prior to event testing:

  ``sudo grep -i "File integrity monitoring scan enabled" /var/ossec/logs/ossec.log``
*Note: Verifying baseline completion is crucial to ensure that subsequent file events trigger immediate inotify kernel events rather than waiting for scheduled differential polling.*

## Testing & Event Execution
A synthetic file modification event was generated within the target monitored directory:

  ``touch /home/labuser/.ssh/fim_test_file``

Observed Telementary & Alert Payload
Upon file modification, Wazuh's real-time inotify watcher triggered a **Level 7 Alert (Rule ID 550).**

``json
  {
    "agent": {
      "id": "003",
      "ip": "192.168.1.40",
      "name": "Endpoint-Linux-01"
    },
    "rule": {
      "id": "550",
      "level": 7,
      "description": "Integrity checksum changed.",
      "mitre": {
        "id": ["T1565.001"],
        "tactic": ["Impact"],
        "technique": ["Stored Data Manipulation"]
      }
    },
    "syscheck": {
      "path": "/home/labuser/.ssh/fim_test_file",
      "mode": "realtime",
      "changed_attributes": ["mtime"],
      "event": "modified",
      "uname_after": "labuser",
      "sha256_after": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  }
``

## Network Telementary & Baseline Analysis
During dashboard and log parsing, surrounding endpoint network chatter was evaluated to distinguish benign infrastructure traffic from potential security threats:

**1. ICMP Type 9 (Router Advertisements):** Multicast traffic (224.0.0.1 / 01:00:5e:00:00:01) was observed and confirmed as standard router advertisement chatter originating from the local gateway interface (Technicolor MAC vendor f8:d0:0e:xx:xx:xx).
**2. Host Firewall Enforcement:** Inspected UFW kernel logs dropping incomming WS-Discovery (UDP 3702) traffic over IPv6 link-local addresses(fe80::) confirming active host-based firewall enforcement.

# Key Takeaways & Practical Lessons

* **Real-time inotify vs Scheduling Polling:** Confirmed that setting realtime="yes" hooks into Linux kernel filesystem events, generating alerts instantaniously upon modification rather than waiting for scheduled interval scans.
* **Cryptographic has Tracking:** Observed how syscheckd tracks SHA-256 and MD5 hashes alongside modification times(mtime) to detect unauthorized file tampering.
* **Framework Alignment:** Verified automated mapping of integrity violations of MITRE ATT&CK T1565.001 (Stored Data Manipulation), NIST 800-53 SI.7, amd PCI-DSS 11.5.
