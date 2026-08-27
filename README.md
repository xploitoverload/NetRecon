> "Every network tells a story. NetRecon helps you read it."

## NetRecon: Local Network Reconnaissance

**NetRecon** is a Python-based network reconnaissance tool built from scratch for discovering and monitoring devices on local networks.

It provides active ARP scanning, passive ARP sniffing, an interactive terminal interface, live host monitoring, TCP port scanning, MAC vendor lookup, known-host labeling, and JSON/CSV export.

Built for **visibility, control, and straightforward network reconnaissance**.

---

### Operator

* **Kalpesh Solanki**
* Contact: [hello@cx330.in](mailto:hello@cx330.in)

---

<p align="center">
  <img src="demo.gif" alt="NetRecon Demo">
</p>

## Why This Exists

NetRecon was built to provide a simple and practical way to discover and monitor devices on a local network.

**See what is connected. Know what is happening.**

---

## Installation

### Requirements

* Python 3
* Linux
* libpcap
* Root privileges for active scanning

### Install from PyPI

The easiest way to install NetRecon is through PyPI:

```bash
python3 -m pip install netreconx
```

Verify the installation:

```bash
netreconx --help
```

For active network scanning, run it with elevated privileges:

```bash
sudo netreconx -i wlan0 -r 192.168.0.0/24
```

### Install from Source

Clone the repository:

```bash
git clone https://github.com/xploitoverload/NetRecon.git
cd NetRecon
```

Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install scapy netifaces rich
```

Verify dependencies:

```bash
python -c "import scapy, netifaces, rich; print('Dependencies OK')"
```

---

## Usage

### Basic Scan

```bash
sudo netreconx
```

### Scan a Specific Network

```bash
sudo netreconx -i wlan0 -r 192.168.0.0/24
```

### Passive Mode

```bash
sudo netreconx -i wlan0 -p
```

### Fast Scan

```bash
sudo netreconx -i wlan0 -r 192.168.0.0/24 -f
```

### Live Monitoring

```bash
sudo netreconx --live --interval 10
```

### TCP Port Scanning

```bash
sudo netreconx -i wlan0 -r 192.168.0.0/24 --ports
```

### JSON Export

```bash
sudo netreconx -r 192.168.0.0/24 --json results.json
```

### CSV Export

```bash
sudo netreconx -r 192.168.0.0/24 --csv results.csv
```

### Parsable Output

```bash
sudo netreconx -r 192.168.0.0/24 -P
```

---

## Options

```text
-i, --iface IFACE       Network interface
-r, --range CIDR        Network range to scan
-l, --list FILE         File containing CIDR ranges
-p, --passive           Passive ARP sniffing
-m, --macs FILE         Known MAC addresses
-F, --filter EXPR       Custom pcap filter
-f, --fast              Fast scan
-c, --count N            ARP request count
-s, --sleep MS           Delay between requests
-S, --suppress           Suppress per-packet sleep
-n, --node OCTET         Source IP last octet
-P, --parsable           Parsable output
-L, --listen             Continue listening
-N, --no-header          Suppress output header
-R, --no-root            Skip root check

--live                   Live device monitoring
--interval SEC           Live scan interval
--ports                  TCP port scanning
--json FILE              JSON export
--csv FILE               CSV export
--verbose                Verbose output
--timeout SEC            ARP timeout
```

---

## Interactive Keys

```text
u       Unique hosts
a       ARP replies
r       ARP requests
j / ↓   Scroll down
k / ↑   Scroll up
.       Page down
,       Page up
h       Help
q       Quit
```

---

## Security

Use NetRecon only on networks and devices you own or are explicitly authorized to test.

Active ARP scanning and TCP port scanning generate network traffic and may trigger network monitoring or security systems.
