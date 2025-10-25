# DSA_ASSIGNMENT_2
# Network Packet Monitor and Replay System 🌐

A multi-threaded C++17 application for capturing, analyzing, and replaying network packets with custom data structures and protocol dissection.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![C++](https://img.shields.io/badge/C++-17-blue.svg)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Output Format](#output-format)
- [Technical Details](#technical-details)
- [Security Notes](#security-notes)
- [Limitations](#limitations)
- [Future Enhancements](#future-enhancements)
- [Contributing](#contributing)
- [License](#license)

## 🔍 Overview

This network monitoring tool captures raw Ethernet packets from a specified network interface, parses multiple protocol layers (Ethernet, IPv4, IPv6, TCP, UDP), filters packets based on IP addresses, and replays selected packets with simulated network delay. The application demonstrates advanced C++ programming concepts including multi-threading, custom data structures, and low-level network programming.

## ✨ Features

- **Raw Packet Capture**: Captures all network traffic on specified interface using AF_PACKET sockets
- **Multi-threaded Pipeline**: Four concurrent threads for capture, dissection, filtering, and display
- **Protocol Dissection**: Parses Ethernet, IPv4, IPv6, TCP, and UDP headers
- **IP-based Filtering**: Filter packets by source and destination IP addresses (with wildcard support)
- **Packet Replay**: Retransmits filtered packets with simulated network delay
- **Custom Data Structures**: Implements Stack and Queue from scratch for educational purposes
- **Real-time Monitoring**: Live display of packet summaries every 5 seconds
- **Retry Mechanism**: Automatic retry logic for failed packet transmissions
- **Thread-safe Operations**: Mutex and condition variable synchronization
- **Graceful Shutdown**: Clean termination with final statistics

## 🏗️ Architecture

```
┌─────────────┐      ┌──────────────┐      ┌─────────────────┐      ┌─────────────┐
│   Capture   │─────▶│  Dissector   │─────▶│ Filter/Replay   │─────▶│   Display   │
│   Thread    │      │    Thread    │      │     Thread      │      │   Thread    │
└─────────────┘      └──────────────┘      └─────────────────┘      └─────────────┘
      │                     │                       │                       │
      ▼                     ▼                       ▼                       ▼
 packetQueue          dissectedQueue           replayQueue            summaryMutex
                                                    │
                                                    ▼
                                              backupQueue
```

### Thread Pipeline

1. **Capture Thread**: Reads raw packets from network interface
2. **Dissector Thread**: Parses protocol layers and extracts IP addresses
3. **Filter/Replay Thread**: Applies filters and retransmits matching packets
4. **Display Thread**: Outputs real-time summaries

## 📦 Requirements

- **Operating System**: Linux (tested on Ubuntu 20.04+)
- **Compiler**: g++ with C++17 support
- **Privileges**: Root/sudo access (required for raw sockets)
- **Libraries**: pthread (for multi-threading)

## 🚀 Installation

### Clone the Repository

```bash
git clone https://github.com/hanan1hub/DSA_ASSIGNMENT_2

```

### Compile

```bash
g++ -std=c++17 -O2 network_monitor.cpp -o network_monitor -pthread
```

## 💻 Usage

### Basic Syntax

```bash
sudo ./network_monitor <interface> <filter-src-ip> <filter-dst-ip>
```

### Parameters

- `<interface>`: Network interface name (e.g., eth0, wlan0, enp3s0)
- `<filter-src-ip>`: Source IP address to filter (use `-` for wildcard/any)
- `<filter-dst-ip>`: Destination IP address to filter (use `-` for wildcard/any)

### Examples

**Monitor all traffic from a specific source IP:**
```bash
sudo ./network_monitor eth0 192.168.1.100 -
```

**Monitor traffic between two specific IPs:**
```bash
sudo ./network_monitor eth0 192.168.1.100 192.168.1.200
```

**Monitor all traffic to a specific destination:**
```bash
sudo ./network_monitor wlan0 - 8.8.8.8
```

**Monitor all traffic (no filtering):**
```bash
sudo ./network_monitor eth0 - -
```

### Finding Your Network Interface

```bash
# List all network interfaces
ip link show

# Or use
ifconfig -a
```

## 📊 Output Format

The application generates five types of packet summaries:

### CAP (Captured)
```
CAP ID=1 size=1514 time=2025-10-25 14:23:01.234
```
Raw packets captured from the interface.

### DSC (Dissected)
```
DSC ID=1 src=192.168.1.100 dst=8.8.8.8 size=1514
```
Packets with parsed protocol information and IP addresses.

### FLT (Filtered)
```
FLT ID=1 src=192.168.1.100 dst=8.8.8.8 size=1514 est_delay(ms)=1.514
```
Packets matching filter criteria with estimated transmission delay.

### REPLAYED (Successfully Transmitted)
```
REPLAYED ID=1 attempts=0 size=1514
```
Packets successfully retransmitted to the network.

### BKUP (Backup/Failed)
```
BKUP ID=47 failed_retries=3 size=1488
```
Packets that failed to replay after maximum retry attempts.

## 🔧 Technical Details

### Custom Data Structures

#### Stack
- Template-based dynamic array implementation
- O(1) amortized push/pop operations
- Automatic resizing (doubles capacity when full)
- Used for protocol layer traversal

#### Queue
- Circular buffer implementation
- O(1) constant-time enqueue/dequeue
- Dynamic resizing with data preservation
- Used for inter-thread packet passing

### Supported Protocols

- **Layer 2**: Ethernet (802.3)
- **Layer 3**: IPv4, IPv6
- **Layer 4**: TCP, UDP

### Thread Synchronization

- **Mutexes**: Protect shared queues and data structures
- **Condition Variables**: Efficient thread wake-up mechanism
- **Atomic Variables**: Lock-free packet ID generation and shutdown signaling
- **RAII Lock Guards**: Exception-safe locking

### Performance Optimizations

- O2 compiler optimization flag
- Minimal lock contention with fine-grained locking
- Circular buffer prevents memory fragmentation
- Amortized O(1) data structure operations

## 🔒 Security Notes

⚠️ **Important Security Considerations:**

- **Root Privileges**: This application requires root access for raw socket operations
- **Network Disruption**: Packet replay can disrupt network services with duplicate packets
- **Isolation**: Only use on trusted/isolated test networks
- **Monitoring**: Be aware of privacy and legal implications when capturing network traffic

**Recommendation**: Use only in controlled lab environments or networks you own/manage.

## ⚠️ Limitations

- Single network interface monitoring at a time
- Limited protocol support (no ICMP, ARP, application-layer protocols)
- No persistent packet storage (in-memory only)
- Basic IPv6 extension header support
- Fixed thread pool (no dynamic scaling)
- Runs for fixed 60-second demo period

## 🚧 Future Enhancements

- [ ] Multi-interface parallel monitoring
- [ ] PCAP file export for offline analysis
- [ ] Advanced filtering (port ranges, protocol types, regex patterns)
- [ ] Real-time statistics dashboard with throughput graphs
- [ ] Configuration file support
- [ ] Deep packet inspection for HTTP, DNS, etc.
- [ ] Web-based GUI for monitoring
- [ ] Packet storage and search capabilities
- [ ] Configurable runtime duration

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Your Name**
- GitHub: [@Hanan Majeed](https://github.com/hanan1hub)
- Email: hmajeed.bsds24seecs@seecs.edu.pk

## 🙏 Acknowledgments

- Linux raw socket programming documentation
- C++17 threading and synchronization references
- Network protocol specifications (RFC documents)

## 📚 References

- [Linux Packet Socket Documentation](https://man7.org/linux/man-pages/man7/packet.7.html)
- [C++ Threading Library](https://en.cppreference.com/w/cpp/thread)
- [TCP/IP Protocol Suite](https://en.wikipedia.org/wiki/Internet_protocol_suite)

---

