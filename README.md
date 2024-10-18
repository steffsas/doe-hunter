# doe-hunter

[![lint-and-test](https://img.shields.io/github/actions/workflow/status/steffsas/doe-hunter/release.yml)](https://github.com/steffsas/doe-hunter/actions/workflows/release.yml)
[![coverage](https://raw.githubusercontent.com/steffsas/doe-hunter/badges/.badges/main/coverage.svg)](/.github/.testcoverage.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/steffsas/doe-hunter/lib?cache=v1)](https://goreportcard.com/report/github.com/steffsas/doe-hunter/lib)

[![Docker](https://img.shields.io/badge/docker-enabled-blue.svg)](https://github.com/steffsas/doe-hunter/pkgs/container/doe-hunter)
[![Renovate](https://img.shields.io/badge/renovate-enabled-blue.svg)](https://github.com/steffsas/doe-hunter/issues/5)

<img src="./img/icon.png" alt="drawing" width="100"/>

----

**DoE-Hunter** is a specialized platform designed for researchers and measurement studies to discover, query, and analyze `Designated Encrypted Resolvers` (DDR) and encrypted DNS protocols like DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), and DNS-over-QUIC (DoQ). This platform supports large-scale scanning and discovery of DNS infrastructure with a focus on the research and analysis of the adoption of encrypted DNS technologies.

## Key Features
- **Research-Oriented DDR and DoE Scanning**: Scans and identifies encrypted DNS resolvers using the DDR mechanism and related DoE protocols based on SVCB/HTTPS DNS records (RFC 9460, RFC 9461, RFC 9462).
- **Large-Scale Measurement**: Built for extensive scans of IPv4 and IPv6 DNS servers, leveraging datasets like ZMap and the IPv6 Hitlist Service.
- **In-Depth Protocol Support**: Automatically identifies and probes encrypted DNS resolvers (DoH, DoT, DoQ) and also runs supplementary scans, such as DNSSEC and EDSR (Encrypted DNS Server Redirection).
- **Pre-built Docker Images**: No manual build steps required thanks to pre-configured Docker images.

## Architecture & Methodology

DoE-Hunter is designed to execute large-scale scans in a modular three-stage architecture:

### Stage 1: DNS Server Discovery
1. **IPv4 Discovery**: Using the ZMap network scanner, the platform identifies responsive DNS servers on the IPv4 address space (port UDP/53).
2. **IPv6 Discovery**: Leveraging the IPv6 Hitlist Service, the platform retrieves responsive IPv6 addresses and performs daily scans to account for IP churn.
   
   In this stage, responsive DNS servers are identified and added to the scan pipeline for further DDR probing.

### Stage 2: DDR Discovery
In the second stage, DoE-Hunter performs DDR discovery by querying DNS servers for Service Binding (SVCB) records to detect encrypted DNS capabilities (e.g., DoH, DoT). This is done using the resolver's IP address or FQDN. If the server supports DDR, the system extracts the encrypted resolver's configuration details (protocols, ports, etc.).

- **DDR Probe Execution**: Queries are sent using the resolver's IP address or FQDN to check for encrypted DNS support.
- **Validation**: If encrypted endpoints are found, the next set of scans (DoE protocols) is scheduled.

### Stage 3: DoE Probing & Other Scans
In the final stage, DoE-Hunter runs in-depth scans on discovered encrypted resolvers:
- **DoH/DoT/DoQ Scans**: Based on DDR results, the platform initiates scans for DNS-over-HTTPS, DNS-over-TLS, and DNS-over-QUIC endpoints.
- **DNSSEC and Certificate Scans**: DoE-Hunter verifies the integrity and security of resolvers by running DNSSEC and TLS certificate scans.
- **Recursive-to-Authoritative Probing**: For in-depth analysis, recursive DNS queries are sent to authoritative servers to detect whether they also support encrypted DNS.

A caching mechanism prevents redundant scans for known resolvers, optimizing scan efficiency and reducing unnecessary network traffic.

## Getting Started

### Requirements
- Docker (v20.10 or higher)
- Docker Compose (v1.29 or higher)
- `.env` file for configuration settings of docker compose

### Installation
1. **Clone the Repository**:
    ```bash
    git clone https://github.com/steffsas/doe-hunter.git
    cd doe-hunter
    ```

2. **Run with Docker Compose**:
    ```bash
    docker compose up -d
    ```

3. **View Logs**:
    ```bash
    docker logs -f doe-hunter
    ```

## Docker Images
The pre-built Docker image can be pulled from GitHub Container Registry (GHCR) and used immediately:
```bash
docker pull ghcr.io/steffsas/doe-hunter:latest
```

## Docker Compose
The `docker-compose.yml` file provides an easy way to run DoE-Hunter in a containerized environment. It includes all necessary service definitions and volume mounts for data persistence.

## Contributing
This platform is aimed at the research community, and we welcome contributions. Please follow the contribution guidelines provided in the repository to get started.

## License
This project is licensed under the MIT License.
