# Lab 01: Zero-Trust Firewall Configuration, Logging, and Custom Alert Generation

## Executive Summary
The goal of this lab was to secure a Linux endpoint using a default-deny firewall posture and establish custom alerting in Wazuh SIEM for blocked incoming network traffic.

Out of the box, Wazuh logged Uncomplicated Firewall (UFW) drops under a generic kernel decoder, which failed to cleanly extract key event details like the targeted destination port. To resolve this visibility gap, I engineered a custom parent/child decoder and custom rule logic to extract essential Layer 3 and Layer 4 fields—including source IP, destination IP, protocol, and target port.

By simulating network probes using Netcat (nc), I verified that dropped connection attempts correctly trigger Level 7 alerts mapped to MITRE ATT&CK (T1046: Network Service Discovery) on the Wazuh dashboard, providing immediate visibility into potential port scanning and reconnaissance.

*Note: In the current iteration, dynamic variable expansion for $(dstport) in the custom rule description required further debugging, so the rule description currently uses a static alert string. My immediate next step is to refine the OSREGEX field mapping in local_decoder.xml to fully leverage variable interpolation in local_rules.xml for faster incident triage.* 

---

## Lab Architecture Overveiw
* **SIEM Manager:** `192.168.1.30` (`Wazuh-Manager-01`)
* **Monitored Endpoint:** `192.168.1.40` (`Endpoint-Linux-01 / Debian Linux`)
* **Detection Mechanism:** Wazuh `syscheckd` engine utilizing Linux kernel `inotify` triggers

---

## 1.Confiuration & Baseline Verification

### 1. Configuration
Configured target enpoint's UFW to deny incoming traffic and allow outgoing traffic by default:

Deny inbound
```bash
~$ sudo ufw default deny incoming
```

Deny Outbound
```bash
~$ sudo ufw default allow outgoing
```

Enabled target endpoint's UFW
```bash
~$ sudo ufw enable
```

Configured the target endpoint's UFW to monitor dropped incomming packets outside of SIEM server:

```bash
sudo nano /var/ossec/etc/ossec.conf
```
Added rule at the bottom of the file inside the <ossec_config></ossec_config> tags:

```xml
<localfile>
    <log_format>syslog</log_format>
    <location>/var/log/ufw.log</location>
</localfile>
```
Added a local rule to fire alerts when packets are dropped by the firewall:

```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```
Added at the bottom of the file inside of the <group></group> tags:

```xml
<rule id="100010" level="7">
    <match>[UFW BLOCK]</match>
    <description>FIREWALL ALERT: UFW dropped incoming packet</description>
    <mitre>
      <id>T1046</id>
    </mitre>
    <group>firewall,custom_alerts,</group>
</rule>
```

### 2.Baseline Verification
Tested to verify changes were done properly and restarted the Wazuh Manager on the server.

  ``sudo /var/ossec/bin/wazuh-analysisd -t``
*Note: Configuration should come back as OK or return nothing to work.*

  ``sudo systemctl restart wazuh-manager``
*Note: Restarts the manager. This is crucial to do if there is any configuration changes in Wazuh.*

## Testing & Event Execution
A Netcat port scan was attempted from the server to the target endpoint to block the traffic, have the firewall log it, and generate an alert on the Wazuh dashboard:

  ``nc -zvw 2 192.168.1.40 9999``

Observed Telementary & Alert Payload
Upon file modification, Wazuh's real-time inotify watcher triggered a **Level 7 Alert (Rule ID 550).**

``json
  {
  "_index": "wazuh-alerts-4.x-2026.08.11",
  "_id": "nF48858BCdFNg2J7HaL-",
  "_version": 1,
  "_score": null,
  "_source": {
    "predecoder": {
      "program_name": "kernel",
      "timestamp": "2026-08-11T19:50:26.674824-04:00"
    },
    "input": {
      "type": "log"
    },
    "agent": {
      "ip": "192.168.1.40",
      "name": "Endpoint-Linux-01",
      "id": "003"
    },
    "manager": {
      "name": "Wazuh-Manager-01"
    },
    "rule": {
      "firedtimes": 10,
      "mail": false,
      "level": 7,
      "description": "FIREWALL ALERT: UFW dropped incoming packet",
      "groups": [
        "local",
        "syslog",
        "sshd",
        "firewall",
        "custom_alerts"
      ],
      "mitre": {
        "technique": [
          "Network Service Discovery"
        ],
        "id": [
          "T1046"
        ],
        "tactic": [
          "Discovery"
        ]
      },
      "id": "100010"
    },
    "location": "/var/log/ufw.log",
    "decoder": {
      "name": "kernel"
    },
    "id": "1786492227.7637965",
    "full_log": "2026-08-11T19:50:26.674824-04:00 Endpoint-Linux-01 kernel: [UFW BLOCK] IN=eno1 OUT= MAC=00:11:22:33:44:55 SRC=192.168.1.30 DST=192.168.1.40 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=53136 DF PROTO=TCP SPT=60444 DPT=9999 WINDOW=64240 RES=0x00 SYN URGP=0 ",
    "timestamp": "2026-08-11T19:50:27.887-0400"
  },
  "fields": {
    "timestamp": [
      "2026-08-11T23:50:27.887Z"
    ]
  },
  "sort": [
    1786492227887
  ]
}
``  

# Key Takeaways & Practical Lessons

* **Log Location and Generation:** UFW writes blocked packet events directly to system log streams (``/var/log/ufw.log`` or ``/var/log/syslog``) via the linux kernel iptables subsystem.
* **Granular Traffic Data:** Each entry for ``[UFW BLOCK]`` captures essential information from Layer 3/4 that's required for incident response. This includes source IP, destination IP, protocol, source port, destination port, and network interface.
* **Noise vs. Signal:** Enabling UFW logging provides visibility for port scanning or other potentially unauthorized inbound probing across the local network (In this case the one endpoint) without overloading cpu resources on endpoints.
* **Default-Deny Configuration:** Provides a better security posture by using ``sudo ufw default deny incoming`` to enforce a zero-trust stance for endpoint network communication. This is done by blocking all incoming connection attempts by default unless explicitly allowed.
* **Proactive Attack Surface Reduction:** Dropping unwanted traffic touching the host firewall prevents unauthorized exposure to unpatched services, dynamic ephemeral ports, or open network listeners.
* **Stateful Filtering:** UFW automatically tracks active outbound connections, allowing return response traffic while dropping unrequested incoming SYN packets.
* **Handling Generic Decoders:** Standard Wazuh decoders may pre-decode UFW kernel messages simply as ``name: kernel``, skipping dynamic field extraction (``scrip``, ``dstport``). I did try to include variables to show the port the connection was attempted through in the alert message, but couldn't figure it out. This was my first attempt at writing a rule so I changed it back to a broad message so I had a working product. I may go back when I get better and re-tune this rule to allow for this to make incident response and triaging easier.
* **Custom Decoder Creation:** Defining a custom parent decoder and then immediately making a child one in ``local_decoder.xml`` using ``<prematch>`` and OSREGEX patterns ensures field mapping (``scrip``, ``dstip``, ``protocol``, ``srcport``, ``dstport``) across firewall events. My theory is having a child predefined and ready can come in handy in future implementation if it works anything like OOP.I may test this in the future.
* **Rule Mapping and Threat Intel:** Custom rules (100010) leveraging ``<decode_as>`` cleanly trigger on decoded events, mapping alerts to MITRE ATT&CK framework techniques-specifically T1046 (Network Service Discovery) to contextualize alerts within standard SOC operations.
* **Controlled Logic Validation:** Using built in tools like ``wazuh-analysisd -t`` verifies XML syntax integrity prior to service restart, preventing manager downtime.
* **Pipeline Simulation:** Running test log lines through ``wazuh-logtest`` confirms Phase 1 (pre-decoding), Phase 2 (decoding & field extraction), and Phase 3 (rule match & alert level) behavior before live deployment.
* **Live Network Verification:** Active probing tools like ``nc -zv -w 2 <target_ip> <port>`` simulate real-world dropped traffic to confirm that kernel logs are generated, ingested by the SIEM agent, and indexed onto the security dashboard in real-time.
