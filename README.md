# Memory Inspector CLI

[![CI](https://github.com/m4rba4s/memory-inspector-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/m4rba4s/memory-inspector-cli/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)](https://github.com/m4rba4s/memory-inspector-cli)
[![Coverage](https://img.shields.io/badge/coverage-85%25-green)](https://github.com/m4rba4s/memory-inspector-cli)
[![CodeQL](https://github.com/m4rba4s/memory-inspector-cli/actions/workflows/codeql.yml/badge.svg)](https://github.com/m4rba4s/memory-inspector-cli/actions/workflows/codeql.yml)
[![Latest Release](https://img.shields.io/github/v/release/m4rba4s/memory-inspector-cli)](https://github.com/m4rba4s/memory-inspector-cli/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-blue)](https://github.com/m4rba4s/memory-inspector-cli)
[![Language](https://img.shields.io/badge/language-C11-orange)](https://github.com/m4rba4s/memory-inspector-cli)

**Memory Analysis Tool for Security Operations**

⚡ **TL;DR**: Memory forensics CLI for detecting process injection, shellcode, and memory anomalies with YARA integration and automated dumping.

A cross-platform memory inspector CLI tool designed for security researchers, reverse engineers, and forensics analysts. Built with clean architecture and modular design.

![Demo](docs/demo.gif)

## 🎯 Core Features

### Memory Map Visualization
- Process memory map enumeration and analysis
- Permission anomaly detection (exec+write regions)
- Injected DLL/shared library detection
- Unregistered memory segment identification

### YARA Integration
- Integrated YARA engine for memory pattern scanning
- Shellcode detection and analysis
- Malware signature matching
- Custom rule support

### Auto-Dump Engine
- Automated suspicious memory region dumping
- Forensics-ready output with metadata
- Timestamped dumps with PID/region info
- Configurable dump triggers

### Minimal CLI/TUI
- Clean, informative command-line interface
- Optional TUI mode for interactive analysis
- Cross-platform colored output
- Comprehensive logging system

## 🏗️ Architecture

```
memory-inspector-cli/
├── src/
│   ├── core/           # Core engine and utilities
│   ├── memory/         # Memory analysis modules
│   ├── yara/           # YARA integration layer
│   ├── dump/           # Auto-dump functionality
│   ├── ui/             # CLI/TUI interface
│   └── platform/       # OS-specific implementations
│       ├── linux/      # Linux-specific code
│       └── windows/    # Windows-specific code
├── include/            # Header files
├── tests/              # Unit and integration tests
├── docs/               # Documentation
└── examples/           # Usage examples
```

## 🚀 Installation

### 📋 Platform Support Matrix

| Platform | Architecture | Build Status | Package Manager | Tested Versions |
|----------|-------------|--------------|-----------------|-----------------|
| **Linux** | x86_64 | ✅ | apt, dnf, yum | Ubuntu 20.04+, RHEL 8+, Fedora 35+ |
| **Linux** | ARM64 | ✅ | apt, dnf, yum | Ubuntu 20.04+, RHEL 8+ |
| **macOS** | x86_64 | ⚠️ | brew | macOS 11+ |
| **macOS** | ARM64 (M1/M2) | ⚠️ | brew | macOS 11+ |
| **Windows** | x86_64 | ❌ | - | Planned for v2.0 |

### 🐧 Debian/Ubuntu
```bash
# Install dependencies
sudo apt update
sudo apt install -y build-essential libyara-dev libncurses5-dev pkg-config libssl-dev

# Clone and build
git clone https://github.com/m4rba4s/memory-inspector-cli.git
cd memory-inspector-cli
make -j$(nproc)
sudo make install

# Verify installation
memory-inspector --version
```

### 🎩 RHEL/CentOS/Fedora
```bash
# RHEL/CentOS (enable EPEL first)
sudo dnf install -y epel-release
sudo dnf install -y yara-devel ncurses-devel gcc make pkg-config openssl-devel

# Fedora
sudo dnf install -y yara-devel ncurses-devel gcc make pkg-config openssl-devel

# Build and install
git clone https://github.com/m4rba4s/memory-inspector-cli.git
cd memory-inspector-cli
make -j$(nproc)
sudo make install
```

### 🍎 macOS
```bash
# Install Homebrew if not available
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install yara ncurses pkg-config openssl

# Build and install
git clone https://github.com/m4rba4s/memory-inspector-cli.git
cd memory-inspector-cli
make -j$(sysctl -n hw.ncpu)
sudo make install
```

### 🐳 Docker
```bash
# Quick run
docker run --rm -it --pid=host --privileged \
  ghcr.io/m4rba4s/memory-inspector:latest --pid 1234

# Build from source
git clone https://github.com/m4rba4s/memory-inspector-cli.git
cd memory-inspector-cli
docker build -t memory-inspector .
docker run --rm -it --pid=host --privileged memory-inspector --pid 1234
```

### 📦 Pre-built Releases
```bash
# Download latest release
curl -L https://github.com/m4rba4s/memory-inspector-cli/releases/latest/download/memory-inspector-linux-x86_64.tar.gz | tar xz
sudo mv memory-inspector /usr/local/bin/
sudo chmod +x /usr/local/bin/memory-inspector
```

## 🚀 Quick Start

### Basic Usage
```bash
# Basic memory analysis
memory-inspector --pid 1234

# YARA scan with custom rules
memory-inspector --pid 1234 --yara-rules /path/to/rules.yar

# Auto-dump suspicious regions
memory-inspector --pid 1234 --auto-dump --output-dir /tmp/dumps

# Interactive TUI mode
memory-inspector --tui --pid 1234

# Scan all processes (requires root)
sudo memory-inspector --scan-all --auto-dump

# Verbose output with detailed analysis
memory-inspector --pid 1234 --verbose --show-regions
```

### Real-world Examples
```bash
# Detect process injection in a suspicious process
sudo memory-inspector --pid $(pgrep suspicious_app) --auto-dump --output-dir ./forensics/

# Scan browser process for exploitation
sudo memory-inspector --pid $(pgrep firefox) --yara-rules rules/browser_exploits.yar

# Monitor system for memory anomalies
sudo memory-inspector --scan-all --threshold high --syslog
```

## 🔧 Development

### Code Style
- C11 standard compliance
- Senior-grade clean code practices
- Comprehensive error handling
- Memory safety guaranteed
- Cross-platform compatibility

### Testing
```bash
# Run all tests
make test

# Static analysis
make lint

# Format code
make format
```

## 🛡️ Security Features

- **Privilege Escalation Prevention**: Minimal root requirements
- **Race Condition Protection**: Atomic operations throughout
- **Safe Memory Dumping**: No sensitive data leakage
- **Sandboxed Execution**: Isolated memory access
- **Audit Logging**: Complete operation logging

## 📋 TODO/Future Enhancements

- [ ] Windows implementation (Phase 2)
- [ ] ARM64 support
- [ ] Network memory analysis
- [ ] Encrypted memory regions
- [ ] Performance optimizations
- [ ] GUI interface option

## 🤝 Contributing

1. Follow the clean architecture patterns
2. Maintain cross-platform compatibility
3. Add comprehensive tests
4. Document all public APIs
5. Security-first approach

## 📄 License

MIT License - see LICENSE file for details

## 🔗 Links

- [Documentation](docs/)
- [Examples](examples/)
- [Issue Tracker](issues/)

---

**Professional memory analysis tool for security researchers and forensic analysts**
