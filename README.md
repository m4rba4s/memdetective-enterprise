# Memory Inspector CLI

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/your-username/memory-inspector-cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Linux-blue)](https://github.com/your-username/memory-inspector-cli)
[![Language](https://img.shields.io/badge/language-C11-orange)](https://github.com/your-username/memory-inspector-cli)
[![Security](https://img.shields.io/badge/security-focused-red)](https://github.com/your-username/memory-inspector-cli)

**Professional Memory Analysis Tool for Blue/Red Team Operations**

A senior-grade, cross-platform memory inspector CLI tool designed for security researchers, reverse engineers, and forensics analysts. Built with clean architecture, modular design, and enterprise-grade security practices.

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

## 🚀 Quick Start (Fedora 42)

### Dependencies
```bash
# Install build dependencies
sudo dnf install -y yara-devel ncurses-devel gcc make pkg-config openssl-devel

# Or use the provided script (requires sudo)
make deps-fedora
```

### Build
```bash
# Clone and build
git clone https://github.com/your-username/memory-inspector-cli.git
cd memory-inspector-cli
make

# Debug build with symbols
make debug

# Clean build
make clean
```

### Usage
```bash
# Basic memory analysis
./memory-inspector --pid 1234

# YARA scan with custom rules
./memory-inspector --pid 1234 --yara-rules /path/to/rules.yar

# Auto-dump suspicious regions
./memory-inspector --pid 1234 --auto-dump --output-dir /tmp/dumps

# TUI mode
./memory-inspector --tui --pid 1234
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

[funcybot@gmail.com]

## 🔗 Links

- [Documentation](docs/)
- [Examples](examples/)
- [Issue Tracker](issues/)

---

**Built with ❤️ by security professionals, for security professionals**
