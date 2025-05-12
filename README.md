# MiniNetGuard

MiniNetGuard is a high-performance, real-time firewall built using **Netfilter**, **Bloom Filters**, and a user-friendly **Streamlit Dashboard**. It efficiently manages packet filtering by integrating with Linux's iptables to intercept and decide whether packets should be accepted or dropped based on a configurable blacklist.

## 📝 **Project Overview**

MiniNetGuard enhances traditional firewall capabilities by providing:

* **Fast IP Lookups**: Uses a Bloom Filter for O(1) time complexity when searching for blacklisted IPs.
* **Real-time Monitoring**: A Streamlit Dashboard displays real-time traffic logs and blacklist updates.
* **Dynamic Blacklist Management**: IP addresses can be added or removed without restarting the firewall.

---
https://www.canva.com/design/DAGnFHajcBo/TeiLeNBd5AkoIK0wVijl4A/edit?utm_content=DAGnFHajcBo&utm_campaign=designshare&utm_medium=link2&utm_source=sharebutton
https://youtu.be/er490PZGA_o?si=5X4IYQdAfluh8fiI

## 📐 **Architecture and Design**

1. **Netfilter (iptables)**:

   * Captures incoming and outgoing packets.
   * Redirects packets to **NFQUEUE** for processing.

2. **Netfilter Queue (NFQUEUE)**:

   * Acts as a bridge to pass packets from kernel space to user space.

3. **MiniNetGuard Firewall**:

   * Written in C, it inspects each packet and consults the **Bloom Filter**.
   * Decides if the packet should be **ACCEPTED** or **DROPPED**.
   * Logs each decision to a real-time log file (`/tmp/firewall_log.txt`).

4. **Streamlit Dashboard**:

   * Monitors live logs of packets.
   * Allows dynamic addition to the blacklist without restarting the firewall.

---

## ⚙️ **Features**

* Fast lookups using **Bloom Filters**.
* Real-time monitoring of accepted and dropped packets.
* Easy-to-use web interface for adding/removing blacklisted IPs.
* Automatic scrolling logs for continuous monitoring.

---

## 🛠️ **Installation Instructions**

```bash
# Clone the repository
git clone https://github.com/yourusername/MiniNetGuard.git
cd MiniNetGuard

# Install dependencies
sudo apt-get install libnetfilter-queue-dev
sudo apt-get install python3-pip
pip3 install streamlit

# Compile the firewall
make
```

---

## 🚀 **Usage Instructions**

1. **Start the firewall**

```bash
sudo ./firewall
```

2. **Run the Streamlit Dashboard**

```bash
streamlit run app.py
```

3. **Access the Dashboard**

   * Open a browser and go to `http://localhost:8501`

---

## 🔄 **Managing the Blacklist**

* Use the Streamlit interface to add/remove IP addresses.
* Changes are immediately applied without restarting the firewall.

---

## 🐞 **Troubleshooting**

* If you encounter `nfq_create_queue failed`, try running with `sudo`.
* Ensure `iptables` is properly configured:

```bash
sudo iptables -A INPUT -j NFQUEUE --queue-num 0
```

* Verify the log path exists: `/tmp/firewall_log.txt`

---

## 💡 **Future Improvements**

* Adding color-coded logs for better visibility.
* Implementing auto-refresh in the Streamlit dashboard.
* Advanced filtering options (e.g., by protocol, source port).

---

## 📜 **License**

This project is licensed under the MIT License.
