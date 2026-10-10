# Network Intrusion Detection System for Industrial Control Systems

Our Network Intrusion Detection System (NIDS) provides users with a means of monitoring network traffic for suspicious patterns and generating alerts on anomalous behavior or signature‑based malicious activity.

---

## Table of Contents

| # | Section |
|---|---------|
| **1** | [System Description and Architecture Overview](#1-system-description-and-architecture-overview) |
| **2** | [NIDS Start-up Guide](#2-nids-start-up-guide) |
| **3** | [Test Instructions](#3-test-instructions) |
| **4** | [Expected Outputs](#4-expected-outputs) |

---

## 1. System Description and Architecture Overview

### 1.1 Overview
Cyber threats targeting internet‑connected systems continue to grow in scale and sophistication. Left unmitigated, these external threats present an unbounded risk that inevitably leads to network compromise, data exfiltration, and potential system destruction. We chose this project to learn how network monitoring can aid in detecting malicious activities before a major compromise. Networks are the backbone of internet communication, which is why we need to start at the root of entry for most malicious attacks. Effective implementation will reduce the amount of lateral damage by leveraging time and acting early against attacks.  

To counter this, network defenders require visibility into network activity with proactive detection before damage occurs. A NIDS provides this visibility by continuously inspecting network traffic, establishing situational awareness of assets and communication flows, and generating a record of events for forensic analysis. By correlating traffic patterns with known attack signatures and identifying deviations from established baselines, NIDS functions as an early‑warning mechanism that helps detect breaches in their early stages. These systems also support detection of lateral movement and insider threats by monitoring internal traffic for suspicious behavior. The resulting event logs enable security teams to reconstruct attack paths, understand root causes, and strengthen defenses against future incidents.

---

### 1.2 Core Architectural Pillars
- Deployed as a Docker-containerized environment.
- Intrusion detection system data lake built on **Elasticsearch** and **Kibana**.
- **Zeek** running natively on the host for high-performance protocol parsing and analysis.
- **Filebeat** running natively on the host to ship parsed log fields into the container.
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

---

## 2. NIDS Start-up Guide

This section provides instructions for installation and environment configuration to get Kibana working and log pipelines ingesting into Elasticsearch.

### 2.1 Setup and Run Elasticsearch & Kibana

1. Configure your host system's kernel memory (so Elasticsearch doesn't crash on boot):
   ```bash
   sudo sysctl -w vm.max_map_count=262144
   ```

2. Clean and launch the Docker infrastructure stack:
   ```bash
   # Navigate to your project directory containing docker-compose.yml
   docker compose down -v --remove-orphans
   docker container prune -f
   docker volume prune -f
   docker image prune -a -f

   # Boot the database environment
   docker compose up -d
   ```
3. Verify infrastructure health:
   ```bash
   docker compose ps
   ```
   Ensure both `elasticsearch-ids` and `kibana-ids` show as healthy.

---

### 2.2 Host System Dependency Configuration

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

#### Native Filebeat Installation (Ubuntu 24.04 LTS)
Run these commands in your host terminal to install the official Elastic Filebeat agent:
```bash
# 1. Download and install the Elastic GPG signing key
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic-archive-keyring.gpg

# 2. Add the official Elastic repository to your sources list
echo "deb [signed-by=/usr/share/keyrings/elastic-archive-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

# 3. Update apt and install Filebeat
sudo apt update && sudo apt install filebeat

# 4. Enable the native Zeek processing module
sudo filebeat modules enable zeek
```

#### Secure Configuration File Permissions
Filebeat requires strict ownership controls to execute its configuration file:
```bash
# Secure the filebeat config file properties
sudo chown root:root filebeat.yml
sudo chmod 644 filebeat.yml

# Ensure script file has executable flags active
chmod +x start_ids.sh
```

#### Setup Python Analytical Dependencies (For Neil's Environment Setup)
```bash
pip install --upgrade pymodbus scapy elasticsearch pandas
```

---

## 3. Test Instructions

### 3.1 Extract and Transform Network Telemetry
Process raw operational PCAP bytes through Zeek to create structured JSON text strings. Ensure you are working from the project root directory.

```bash
# 1. Use native Zeek engine to parse the network traces into JSON formatted logs
zeek -r ./modbus_test.pcap policy/tuning/json-logs.zeek Log::default_logdir="./zeek_logs"

# 2. Fire up your host Filebeat shell script framework to ship logs directly into Docker
./start_ids.sh
```

---

### 3.2 View Modbus Logs in Kibana
1. Open your web browser and go to: `http://localhost:5601`
2. Click the **Hamburger Menu** (three horizontal lines) in the top-left corner.
3. Scroll down and click on **Discover** (under the Analytics section).
4. Since this is your first time loading data, Kibana will ask you to create a Data View:
   - **Name:** `Modbus IDS`
   - **Index Pattern:** `filebeat-*`
   - **Timestamp field:** `@timestamp`
   - Click **Create (or Save) data view**.
5. Set your target timeframe filter in the top right to **"All time"** to populate historical data.

You should immediately see a timeline graph spike up and rows of parsed Modbus metadata text populate below it.

---

## 4. Expected Outputs

The expected outcome is to successfully detect malicious traffic while minimizing false positives. The output will be displayed on a custom designed dashboard, which provides key trends in network activity and alerts. The NIDS will be tested using an example scenario that transmits captured network traffic containing routine network activity and known malicious activity. Custom security rules will be used to identify malicious activity and raise alerts during the test scenario. The NIDS performance will be evaluated based on the alert generation and the detection rate, which limits false positives.