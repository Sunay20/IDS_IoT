# Lightweight IoT Intrusion Detection & Prevention System (IDS/IPS)

This project is a machine learning-based Intrusion Detection and Prevention System specifically designed for Internet of Things (IoT) edge devices (like smart routers or Raspberry Pis). 

IoT environments are characterized by low-compute power and highly predictable, low-bandwidth network traffic. This project trains an IDS on the `RT_IOT2022` dataset, prunes it down to the top 10 most critical network flow features, and deploys it as an active, real-time network shield capable of instantly dropping malicious connections.

## 🚀 Architecture overview

The project is split into two primary phases: Model Training (Offline) and Live Inference (Real-Time).

### 1. Training Pipeline
* **`iot.py`**: The core ML training script. It loads the massive `RT_IOT2022` dataset, cleans it, and trains a full Random Forest model. To make it suitable for IoT devices, it performs **Model Pruning**, extracting the Top 10 most important features. It then trains and saves a "Lightweight" version of the model (`iot_detector_light.pkl`) and saves the exact feature layout.

### 2. Auditing & Testing Scripts
* **`detector.py`**: An offline auditing script. It loads the lightweight model and evaluates its accuracy against the exact 20% unseen test split generated during training, ensuring zero data leakage.
* **`test_random_samples.py`**: A dynamic testing script that plucks 15 random rows from the raw dataset, dynamically preprocesses them, and runs an on-the-fly accuracy check.
* **`test_new_data.py`**: A manual testing script that takes 100% synthetic, manually constructed Python dictionaries mimicking attacks (like `DOS_SYN_Hping`) and passes them through the model to prove it generalizes beyond the CSV file.

### 3. The Real-Time Network Shield
* **`live_sniffer.py`**: The crown jewel of the project. This script binds directly to your Windows Wi-Fi/Ethernet network interface card using `NFStream` and `Npcap`. 
    * It intercepts live network packets.
    * It calculates complex mathematical network flow statistics in real-time.
    * It feeds those statistics to the lightweight ML model.
    * **Automated Prevention:** If it detects an IoT attack (like a Mirai Botnet DDoS attempt or Lateral Movement ARP poisoning), it immediately captures the attacker's IP and executes an automated operating system firewall command to quarantine the hacker.

## 🛠 Prerequisites

To run the real-time `live_sniffer.py` on Windows, you must have the underlying C++ network drivers installed:

1. Download **Npcap** from [npcap.com](https://npcap.com/).
2. Run the installer and **check the box for "Install Npcap in WinPcap API-compatible Mode"**.
3. Install Python dependencies:
   ```bash
   pip install pandas numpy scikit-learn joblib matplotlib seaborn nfstream psutil
   ```

## 🎮 How to Use

**Step 1: Train the Model**
Generate the lightweight models and test data splits.
```bash
python iot.py
```

**Step 2: Audit the Accuracy**
Ensure the lightweight model performs well on unseen test data.
```bash
python detector.py
```

**Step 3: Run the Live Shield**
*(Requires Administrator Privileges)*
```bash
python live_sniffer.py
```
*Note: Because this model is trained strictly on IoT traffic, running this on a personal laptop streaming Netflix or YouTube will generate false-positive alerts, as standard PC traffic looks mathematically identical to an IoT DDoS attack. It is meant to be deployed on an IoT gateway!*

## 🛡 Targeted Attacks Detected
The ML model is actively trained to identify and mitigate:
* `DOS_SYN_Hping` (TCP SYN Floods)
* `ARP_poisioning` (Lateral Movement / Man-in-the-Middle)
* `MQTT_Publish` (Protocol Exploitation)
* `DDOS_Slowloris`
* `NMAP_XMAS_TREE_SCAN` (Reconnaissance)
* *...and more.*
