# Wazuh Home Lab & Security Engineering Journal
*A running collection of my Wazuh home lab journeys, custom detection rules, and endpoint security experiments built outside of work.*


## Introduction
Welcome! This repository documents my hands-on security engineering experiments, custom detection rules, and telemetry investigations conducted in my home lab. 

The primary goal of this repository is to bridge theoretical cybersecurity concepts with practical execution. Here, I test host-based detection mechanisms, evaluate real-time telemetry, analyze system logs, and map observed security events to industry frameworks like MITRE ATT&CK and NIST 800-53.

I am new to documentation and trying mark down for the first time as a medium for documenting my work. This is mentioned because some of my documentation might look a little wacky for a bit so bare with me while I vibe code this out first and get a feel for it as I go. I would rather do this than not document what I've been doing like I have in the past. Thank you for visiting this repo and snooping!

---

## Lab Architecture Overview
* **Wazuh SIEM Manager:** `192.168.1.30` (`Wazuh-Manager-01`)
* **Monitored Linux Endpoint:** `192.168.1.40` (`Endpoint-Linux-01`)
* **Default Gateway:** `192.168.1.1`
* **Subnet:** `192.168.1.0/24`
* **Core Technologies:** Wazuh SIEM, `syscheckd` (`inotify`), UFW, OpenSSL, bash/Python scripting

---

## Lab Articles & Documentation Index

### [Lab 01: Firewall Configuration, Traffic Logging, and Alert Generation](./labs/01-firewall-logging-alerts.md)
* **Topics:** UFW, Host-Based Firewall Rules, Syslog Parsing, Wazuh Alert Rules, Network Telemetry
* **Summary:** Reconfigured host firewall rules, enabled kernel-level traffic logging for dropped packets, and ingested UFW telemetry into Wazuh to generate real-time security alerts.

*(New lab write-ups and articles will be added here as experiments are completed.)*

### [Lab 02: Real-Time File Integrity Monitoring (FIM) & Telemetry Validation](./labs/02-fim-realtime-ssh.md)
* **Topics:** HIDS, Real-Time Inotify Triggers, Log Telemetry Parsing, MITRE ATT&CK T1565.001
* **Summary:** Configured real-time monitoring on sensitive SSH directories, validated Level 7 integrity alerts upon file modification, and analyzed underlying network baseline chatter (ICMP Type 9 and UFW multicast drops).

---

## Repository Structure
```text
.
├── README.md               # Main repository introduction & article index
├── LICENSE                 # MIT License
├── .gitignore              # Git exclusion rules
└── labs/                   # Individual lab articles & detailed write-ups
    └── 01-fim-realtime-ssh.md
