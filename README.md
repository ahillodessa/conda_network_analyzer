# Multi-platform Network Analyzer (C++20)

## Description
A high-performance command-line network traffic analyzer built with modern C++20. The application captures real-time network packets and extracts source/destination IP addresses and protocols.

### Features
* **Real-time Packet Capture**: Leverages `libpcap` for low-level network monitoring.
* **Modern C++20 Core**: Utilizes `std::span` for zero-copy data handling and `Concepts` for header validation.
* **Smart CLI**: Advanced argument parsing (interface selection, packet count) via `CLI11`.
* **Cross-Platform**: Fully compatible with Linux, macOS, and Windows (via Npcap/WinPcap).
* **Enhanced Logging**: Clean and fast console output using the `fmt` library.

## Build system
* **Conda/Rattler-Build**: Automated packaging for the Conda ecosystem.
* **CMake & Ninja**: Fast, reproducible builds across different compilers (GCC, Clang, MSVC).
* **Pixi**: Modern environment management for development and CI/CD pipelines.

## Testing
* **CI/CD Pipeline**: Integrated GitHub Actions for automated building on `ubuntu-latest`, `macos-latest`, and `windows-latest`.
* **Functional Integration Tests**: 
  - Automated packet capture verification on Linux (Ubuntu) using `sudo` and background traffic generation.
  - Linkage and library integrity checks on macOS and Windows.
* **Manual Verification**: Validated on local virtual environments.

## Source
https://github.com/ahillodessa/conda_network_analyzer

## License
This project is licensed under the **MIT License**.
