# Network Intrusion Detection System for Industrial Control Systems

Our Network Intrusion Detection System (NIDS) provides users with a means of monitoring network traffic for suspicious patterns and generating alerts on anomalous behavior or signature‑based malicious activity.

---

## Table of Contents

| # | Section |
|---|---------|
| **1** | [System Description and Architecture Overview](#1-system-description-and-architecture-overview) |
| **2** | [NIDS Start-up Guide](#2-nids-start-up-guide) |
| **3** | [Sample Rule Instructions](#3-sample-rule-instructions) |
| **4** | [Creating a New Security Rule](#4-creating-a-new-security-rule) |
| **5** | [Expected Outputs](#5-expected-outputs) |

---

## 1. System Description and Architecture Overview

### 1.1 Overview
Cyber threats targeting internet‑connected systems continue to grow in scale and sophistication. Left unmitigated, these external threats present an unbounded risk that inevitably leads to network compromise, data exfiltration, and potential system destruction. We chose this project to learn how network monitoring can aid in detecting malicious activities before a major compromise. Networks are the backbone of internet communication, which is why we need to start at the root of entry for most malicious attacks. Effective implementation will reduce the amount of lateral damage by leveraging time and acting early against attacks.  

To counter this, network defenders require visibility into network activity with proactive detection before damage occurs. A NIDS provides this visibility by continuously inspecting network traffic, establishing situational awareness of assets and communication flows, and generating a record of events for forensic analysis. By correlating traffic patterns with known attack signatures and identifying deviations from established baselines, NIDS functions as an early‑warning mechanism that helps detect breaches in their early stages. These systems also support detection of lateral movement and insider threats by monitoring internal traffic for suspicious behavior. The resulting event logs enable security teams to reconstruct attack paths, understand root causes, and strengthen defenses against future incidents.

---

### 1.2 Core Architectural Pillars
- Deployed as a Docker-containerized environment.
- Intrusion detection system data lake built on **Elasticsearch** and **Kibana**.
- **Zeek** running natively on the host for high-performance protocol parsing and d analysis.
- **Filebeat** running natively on the host (via `filestream` NDJSON ingestion) to ship parsed `modbus.log` fields directly into the Elasticsearch container.
- **Pymodbus** / Python scripts for custom data querying and automated threat analysis.

#### 1.2.1 Infrastructure & Preliminary WSL Setup (Windows Host)
1. Prepare the WSL to run the project. In the terminal run this command:
   ```bash
   wsl --install -d Ubuntu
   ```
2. Define Ubuntu as the main distribution:
   ```bash
   wsl --set-default Ubuntu
   wsl --list --verbose
   ```
3. Connect VS Code to your environment:
   - Type `Ctrl + Shift + P`
   - Select “WSL: Connect to WSL”
4. Configure Docker Desktop WSL Integration:
   - Click on **Settings** -> **Resources** -> **WSL Integration**
   - Toggle **Enable integration with my default WSL distro** -> Check **Ubuntu**
   - Restart Docker Desktop
5. Verify versions inside your WSL terminal:
   ```bash
   docker version
   docker compose version
   ```
6. Add user permissions for Docker commands without sudo:
   ```bash
   sudo usermod -aG docker $USER
   ```
7. Restart your WSL environment:
   ```bash
   wsl --shutdown
   ```
   Reopen your terminal and VS Code to apply group changes.

8. Configure your host system's kernel memory (so Elasticsearch doesn't crash on boot):
   ```bash
   sudo sysctl -w vm.max_map_count=262144
   ```
---
### 1.2.2 Host System Dependency Configuration

#### Native Zeek Installation (Ubuntu 24.04 LTS)
Deploy the core Long Term Support (LTS) analysis engine directly onto the host terminal:
```bash
# Add official network monitor source tree
echo 'deb https://opensuse.org /' | sudo tee /etc/apt/sources.list.d/zeek.list
sudo wget -nv https://opensuse.org -O /etc/apt/trusted.gpg.d/zeek.asc

# Install application binaries
sudo apt update
sudo apt install zeek-lts
```
*(Note: During package setup prompts for the Postfix Mail wizard, select **No Configuration** to reduce background system load).*

#### Link Zeek Binaries to PATH for CLI Use
```bash
echo "export PATH=\$PATH:/opt/zeek/bin" >> ~/.bashrc
source ~/.bashrc
```
### Extract Zeek Logs from Pcap (Optional)
Process raw operational PCAP bytes through Zeek to create structured JSON text strings. Ensure you are working from the project root directory.

```bash
# 1. Create the output directory for Zeek logs
mkdir -p ./zeek_logs

# 2. Use native Zeek engine to parse the network traces into JSON-formatted logs
zeek -r ./modbus_test.pcap policy/tuning/json-logs.zeek Log::default_logdir="./zeek_logs"

```

#### Native Filebeat Installation (Ubuntu 24.04 LTS)
Run these commands in your host terminal to install the official Elastic Filebeat agent:
```bash
# 1. Download and install the Elastic GPG signing key
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic-archive-keyring.gpg

# 2. Add the official Elastic repository to your sources list
echo "deb [signed-by=/usr/share/keyrings/elastic-archive-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

# 3. Update apt and install Filebeat
sudo apt update && sudo apt install filebeat

# Note: Zeek Modbus JSON log ingestion is configured directly via the filestream input in filebeat.yml.
```
---

#### Setup Python Analytical Dependencies (For Neil's Environment Setup)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pymodbus scapy elasticsearch pandas
```
---
## 2. NIDS Start-up Guide

Start here if you already have dependencies installed. This section provides instructions for installation and environment configuration to get Kibana working and log pipelines ingesting into Elasticsearch. 
 - Password-protected accounts are required for the Elastic Security Rules and Alerts to function. The script `init-passwords.sh` sets the passwords in Elastic from the environment variables. 

### 2.1 Setup and Run Elasticsearch & Kibana

1. Grab the latest changes from the remote repo:
   ```bash
   git pull origin main
   ```

2. Set up local credentials and launch the Docker infrastructure stack:
   ```bash
   test -f .env || cp .env.example .env
   ```
   The default admin username / password for kibana is `elastic` / `elastic`.

   #### Secure Configuration File Permissions
   Set permissions for `filebeat.yml` and the shell scripts:
   ```bash
   # Filebeat standard user account permissions to prevent permission issues
   sudo chmod 644 filebeat.yml

   # Ensure script file has executable flags active
   chmod +x init-passwords.sh start_ids.sh
   ```
   Rebuild the containers and delete the attached volumes (-v): 
   ```bash
   docker compose down -v
   docker compose up -d
   ```
   Elasticsearch security is enabled. Compose initializes the built-in `kibana_system` service account from `.env` before starting Kibana.

3. Verify infrastructure health:
   ```bash
   docker compose ps
   ```
   Ensure both `elasticsearch-ids` and `kibana-ids` show as `Up`, and that `init-passwords` complete without errors.

   Elasticsearch (`localhost:9200`) and Kibana (`localhost:5601`) are published on localhost only. `start_ids.sh` automatically loads `.env` when shipping logs.

4. Run the host Filebeat wrapper script (auto-loads .env and PROJECT_DIR) to ship logs into Docker:
   ```bash
   ./start_ids.sh
   # Note: ctrl + c to exit.
   ```
---

## 3. Sample Rule Instructions
The logs from 11/3 11:47 to 11:50 have 3 hosts:
   - HMI: 192.168.2.20
   - PLC: 192.168.2.10
   - Attacker: 192.168.5.50

The rule detects the attacker reading and writing to the PLC. 

### 3.1 Import Security Rule and Data Filter
Import security rule and data filter for the sample logs:
```bash
# Import the filter
curl -u elastic:elastic -X POST "http://localhost:5601/api/saved_objects/_import" -H "kbn-xsrf: true" --form file=@DataFilter.ndjson

# Import the rule
curl -u elastic:elastic -X POST "http://localhost:5601/api/detection_engine/rules/_import" -H "kbn-xsrf: true" --form file=@Roge_device_rules_export.ndjson
```
In the main Discover View you'll see a timeline graph and rows of parsed Modbus metadata under the `zeek.modbus.*` fields (such as `zeek.modbus.func`, `zeek.modbus.unit`, `zeek.modbus.id.orig_h`, and `zeek.modbus.id.resp_h`).

### 3.2 Log-in and View Modbus Logs via Kibana
1. Open your web browser and go to: `http://localhost:5601`
2. Log in using the elastic superuser username and the ELASTIC_PASSWORD defined in your .env file.
   (Default: `elastic / elastic`)

### 3.3 View Security Rule
To see the rule running in Elastic via Kibana:

1. Open the left **Hamburger Menu** (the three horizontal lines in the top left corner).
2. Under the **Security** section, click on **Rules**.
3. Select **Detection rules (SIEM)** from the dropdown.
4. The resulting table displays all active and inactive rules. You can view their current status, last execution time, and any recent failures.

### Note: If the Modus IDS datastream is not listed:
a. Click the **Hamburger Menu** (three horizontal lines) in the top-left corner.
b. Scroll down and click on **Discover** (under the Analytics section).
c. Since this is your first time loading data, select `Create data view`:
   - **Name:** `Modbus IDS`
   - **Index Pattern:** `filebeat-*`
   - **Timestamp field:** `@timestamp`
   - Click **Create (or Save) data view**.
c. Set your target timeframe filter in the top right to **"All time"** to populate historical data.

---
## 4. Creating a New Security Rules

To create a new alert, follow these steps:

### Step 1: Define the Rule Type
1. From the **Detection rules (SIEM)** page, click the **Create new rule** button in the top right.
2. Select **Custom query** from the *Select rule type* menu. 
   *(Note: Use **Threshold** if you are building an excessive polling rule).*
3. Ensure your index patterns include `filebeat-*` (or the specific index where your Zeek logs are routed).

### Step 2: Build the Query
1. In the **Custom query** box, enter your KQL (Kibana Query Language) logic. 
2. Click **Preview results** to test if your query successfully catches historical data without triggering false positives.

**Example Modbus Queries:**
*   **Rogue Write Commands:** 
    `zeek.modbus.func : ("WRITE_MULTIPLE_COILS" or "WRITE_MULTIPLE_REGISTERS" or "WRITE_SINGLE_COIL" or "WRITE_SINGLE_REGISTER") and not zeek.modbus.id.orig_h : "192.168.2.20"`

### Step 3: About the Rule
1. Click **Continue**.
2. Give your rule a descriptive **Name** (e.g., "Detected Rogue Device Write Command").
3. Assign a **Description**, **Severity** (e.g., High), and **Risk score** (e.g., 73).

### Step 4: Schedule and Actions
1. Click **Continue**.
2. Set the rule schedule. A standard baseline is to run every **5 minutes** with a 1-minute look-back overlap.
3. In the **Rule actions** section, to populate the Kibana UI without external alerts, you can leave this blank.
4. Click **Create & enable rule** at the bottom of the screen.

## 4.1 Investigating Rule Alerts

Once a rule triggers, you can investigate the alert:
1. Navigate to **Security** -> **Alerts**.
2. Locate the alert generated by your new rule.
3. Click the **Expand** (diagonal arrows) icon next to the alert to view the raw JSON or Table data, which will expose the underlying custom Zeek fields (like `zeek.modbus.func`).
4. Click the **Investigate in timeline** icon to open a customizable workspace where you can add your specific `zeek.modbus` fields as visible columns.
---

## 5. Expected Outputs

The expected outcome is to successfully detect malicious traffic while minimizing false positives. The output will be displayed on a custom designed dashboard, which provides key trends in network activity and alerts. The NIDS will be tested using an example scenario that transmits captured network traffic containing routine network activity and known malicious activity. Custom security rules will be used to identify malicious activity and raise alerts during the test scenario. The NIDS performance will be evaluated based on the alert generation and the detection rate, which limits false positives.