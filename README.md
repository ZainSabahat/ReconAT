# ReconAT - Comprehensive Reconnaissance Automation Tool

This Python script automates the reconnaissance process for a given target domain. It leverages a suite of popular open-source tools to perform a wide range of enumeration and analysis tasks, from subdomain discovery to vulnerability scanning. The entire workflow is consolidated into a single, easy-to-use script that organizes all results into a structured directory for later review.

## Features

-   **Subdomain Enumeration:** Discovers subdomains using **Subfinder** and **Chaos**.
-   **Advanced Subdomain Discovery:** Utilizes **Regulator** and **PureDNS** for advanced subdomain brute-forcing and resolution.
-   **Live Host Detection:** Identifies active and responsive subdomains using **HTTPX**.
-   **IP Address Discovery:** Gathers related IP addresses from **Shodan** based on hostname, SSL certificate, and CN.
-   **Virtual Host Scanning:** Scans discovered IPs for virtual hosts using **FFUF**.
-   **Directory Brute-Forcing:** Runs directory discovery on all live subdomains with **FFUF**.
-   **Port Scanning:** Scans all discovered subdomains for the top 1000 open ports using **Naabu**.
-   **Vulnerability Parameter Mining:** Gathers URLs from the Wayback Machine (**gau**) and scans them for potential XSS (**kxss**) and Open Redirect (**Oralyzer**) vulnerabilities.
-   **Dorking Links:** Generates a convenient HTML file with pre-made dorking links for Google, Whoxy, and FOFA.
-   **Slack Notifications:** Sends a notification to a specified Slack webhook upon completion of the scan.

## Workflow

```
Target Domain
      |
      +--> Subfinder & Chaos (Subdomain Enumeration)
      |
      +--> Regulator & PureDNS (Advanced Subdomain Discovery)
      |
      +--> HTTPX (Find Alive Hosts)
      |
      +--> Shodan (Find Associated IPs)
      |      |
      |      +--> FFUF (VHost Scanning on IPs)
      |
      +--> Naabu (Port Scanning on Subdomains)
      |
      +--> FFUF (Directory Brute-Force on Alive Subdomains)
      |
      +--> GAU, GF, uro, kxss, Oralyzer (Vulnerability Parameter Mining)
      |
      +--> Generate Dorking Links & Send Slack Notification
```

## Installation & Setup

Follow these steps to set up the tool and its dependencies.

### 1. Clone the Repository

```bash
git clone https://github.com/ZainSabahat/ReconAT
cd ReconAT
```

### 2. Install Python Libraries

The script and its dependencies require a few Python libraries.

```bash
pip install requests shodan uddup
```

### 3.1 Install Required Tools

This script is a wrapper around several powerful command-line tools. You must install all of them and ensure they are accessible in your system's `PATH`.

### 3.2 Go-based Tools

You can install most of these using the `go install` command.

-   [**Subfinder**](https://github.com/projectdiscovery/subfinder)
-   [**Chaos**](https://github.com/projectdiscovery/chaos-client)
-   [**HTTPX**](https://github.com/projectdiscovery/httpx)
-   [**FFUF**](https://github.com/ffuf/ffuf)
-   [**Naabu**](https://github.com/projectdiscovery/naabu)
-   [**Gau**](https://github.com/lc/gau)
-   [**GF**](https://github.com/tomnomnom/gf)
-   [**KXSS**](https://github.com/Emoe/kxss)
-   [**PureDNS**](https://github.com/d3mondev/puredns)

You can typically install most of the Go-based tools using:
```bash
go install -v <tool-repo-path>@latest
```

### 3.3 Python-based Tools

**Regulator**

The script assumes this is cloned into `~/regulator`.

```bash
git clone https://github.com/cramppet/regulator.git
pip install -r ~/regulator/requirements.txt
```

**Oralyzer**

The script assumes this is cloned into `~/Oralyzer`.

```bash
git clone https://github.com/r00tkie/Oralyzer.git
pip install -r ~/Oralyzer/requirements.txt
```

**uro**

```bash
git clone https://github.com/cramppet/regulator.git
pip install -r ~/regulator/requirements.txt
```

### 3.4 Setup GF and Gf-Patterns

For `gf` to work correctly with vulnerability patterns, you need to set it up with a good pattern repository.

```bash
# Follow the complete setup guide at:
# https://github.com/1ndianl33t/Gf-Patterns
```

### 3.5 Dependencies and Other Tools

- **massdns (for PureDNS):**

```bash
git clone https://github.com/blechschmidt/massdns.git
cd massdns
make
sudo make install
```

- **Resolvers List (for PureDNS):** A list of trusted DNS resolvers is required for `PureDNS`.

```bash
wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -O ~/regulator/resolvers.txt
```

- **Dig:** Usually pre-installed on Linux/macOS. If not, install `dnsutils` (Debian/Ubuntu)

### 4. Configuration

Before running the script, you need to configure your API keys. It is highly recommended to set them as environment variables.

```bash
export CHAOS_KEY='YOUR_CHAOS_API_KEY'
export SHODAN_API_KEY='YOUR_SHODAN_API_KEY'
```

You can also modify the configuration variables at the top of the script to change file paths or the Slack webhook URL.

## Usage

To run the script, make it executable and provide a target domain as an argument.

```bash
# Make the script executable
chmod +x recon.py

# Run the scan
./recon.py example.com
```

The script will print its progress to the console and create a directory structure containing all the output files.

### Output Structure

All results will be saved in the `~/ReconAT/recon-results/` directory, organized by the target's name.

```
recon-results/
└── [example.com/](https://example.com/)
    ├── example.com-subdomains.txt
    ├── alive_subdomains.txt
    ├── ips.txt
    ├── example.com-portscan.txt
    ├── parameterized-urls.txt
    ├── illegal-characters-check.txt
    ├── dork_links.html
    ├── ffuf-results/
    │   ├── sub.example.com-ffuf.html
    │   └── ...
    └── vhosts-scan/
        ├── 1.2.3.4.html
        └── ...
```

## Disclaimer

This tool is intended for educational purposes and for security professionals to use in authorized security assessments. Do not use this tool for any illegal activities. The author is not responsible for any misuse or damage caused by this script.
