# Dynamic_enum_Wizard

**Dynamic_enum_Wizard** is a curses-based wizard that conducts a wide range of security reconnaissance tasks while keeping the terminal output to a minimum. All detailed logs and data are stored in a dedicated workspace folder. This approach lets you see just enough progress on screen—plus a spinner with optional CPU/Memory stats—while the real work is logged to disk.

---

## Features

### Wizard-Style Prompts
- **Domain input** (with basic validation)
- **AMASS brute-forcing** (enabled or disabled)
- **Port Scanning** approach (Common ports, Top 1000, or All 65535)
- **Directory Brute-Forcing** wordlist choice (common/big)
- **Optional Concurrency** for DNS resolution, Dirb, GoWitness, Naabu, etc.

### WHOIS & DNS
- WHOIS queries to glean ownership and registrar info.
- DNS resolution (with optional concurrency) to map subdomains to IPs.

### Subdomain Enumeration
- Integrates `subfinder`, `assetfinder`, `sublist3r`, and `amass` (passive and active) to gather a comprehensive subdomain list.

### Port & Service Scanning
- `nmap` with user-chosen port range.
- `naabu` for quick port scanning to find open TCP ports fast.

### SSL Certificate Checks
- Uses `openssl s_client` to fetch certificate data on port 443 for each subdomain.

### Directory Brute-Forcing
- `dirb` on both HTTP and HTTPS, using either a “common” or “big” wordlist chosen by the user.

### Screenshot Capture
- `GoWitness` quickly captures HTTP/HTTPS screenshots of subdomains.

### Exploit Search
- `searchsploit` on discovered `nmap` service banners to find related vulnerabilities.

### Minimal Curses UI
- ASCII banner at the top, short progress lines, and a spinner on the bottom row that can display CPU/Mem usage if `psutil` is installed.

### Execution Timeline
- Logs major step start/end times, generating an ASCII timeline at the end.

---

## Prerequisites & Installation

### System Requirements
- A Debian/Ubuntu/Kali-based system (due to `apt-get` usage).
- Python 3.6+
- `sudo/root` privileges (for installing missing packages).

### Clone the Repo
```bash
git clone https://github.com/exfil0/dynamic_enum_wizard.git
cd dynamic_enum_wizard
```

### Make Executable
```bash
chmod +x interactive_enum_wizard.py
```

### (Optional) Install `psutil`
```bash
sudo apt-get install python3-psutil
```
or
```bash
sudo pip3 install psutil
```
This enables the spinner to display real-time CPU and memory usage.

---

## Usage

### Run as sudo
```bash
sudo ./interactive_enum_wizard.py
```

### Follow the Wizard
- **Domain**: E.g., `example.com`
- **AMASS brute**: `y/n`
- **Port scanning approach**:
  1. Common (80,443)
  2. Top 1000 (default `nmap`)
  3. All (65535)
- **Directory brute-forcing wordlist**: common or big
- **Concurrency**: `y/n` for parallel DNS, Dirb, GoWitness, etc.

### Check the Workspace
- A new folder `wizard_enum_<domain>` is created.
- Detailed logs in subfolders:
  - `logs/`
  - `nmap_scans/`
  - `dirb_scans/`
  - `ssl_certs/`
  - `exploits/`
  - `gowitness_shots/`
- An ASCII timeline of major step durations is displayed at the end of the run.

---

## Example Session
```bash
$ sudo ./dynamic_enum_wizard.py

      :::::::::       ::::::::::     :::       ::: 
     :+:    :+:      :+:            :+:       :+:  
    +:+    +:+      +:+            +:+       +:+   
   +#+    +:+      +#++:++#       +#+  +:+  +#+    
  +#+    +#+      +#+            +#+ +#+#+ +#+     
 #+#    #+#      #+#             #+#+# #+#+#    Exfil0   
#########       ##########       ###   ###      v1.0   

~ Mapping the Attack Surface for Maximum Exploitation ~

[*] Loading Recon Wizard (Now with Naabu, GoWitness, Concurrency...)


[?] Target domain (e.g., example.com): scarybyte.com
[?] Enable AMASS brute force? (y/N): n

Port scanning approach (for Nmap, sublist3r, amass):
  1) Common HTTP/HTTPS only (80,443)
  2) Extended Common Ports => top 1000
  3) All 65535 TCP ports
[?] Enter 1, 2, or 3: 1

Directory brute-force wordlist options:
   1) common.txt
   2) big.txt
[?] Choose 1 or 2: 1

[?] Enable concurrency for DNS, Dirb, GoWitness, Naabu? (y/N): y

-- The script runs with a spinner at the bottom, minimal lines above, logs in 'wizard_enum_scarybyte.com' --
```

---

## License
This project is licensed under the MIT License for simplicity and permissiveness, allowing commercial and private use with minimal restrictions.

```text
MIT License

Copyright (c) 2025 ...

Permission is hereby granted, free of charge, to any person obtaining a copy ...
```

---

## Disclaimer
- **Authorized Use Only**: This tool is intended for legal security testing and educational research. Ensure you have explicit permission before scanning any domain/IP.
- **No Warranty**: Provided “as is,” without warranty of any kind. The authors assume no liability for damage or misuse.
- **Rate-Limits & CAPTCHAs**: Some tools may be detected by firewalls or lead to CAPTCHAs. Use responsibly.

---

## Contributing
1. Fork the repo and create a new branch (`feature/something` or `fix/issueX`).
2. Submit a Pull Request with a clear description of your changes.
3. Ensure new features or bug fixes are well-tested.
4. For major changes, please open an issue first to discuss the changes.

We welcome:
- Concurrency improvements
- Additional tool integrations
- Advanced scanning logic
