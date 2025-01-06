#!/usr/bin/env python3
# encoding: UTF-8

__author__     = "Exfil0"
__license__    = "GPLv3"
__version__    = "1.1"
__maintainer__ = "Exfil0"

import os
import re
import sys
import csv
import json
import time
import shutil
import curses
import logging
import threading
import platform
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import psutil  # For CPU & MEM usage in spinner
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# If you want to fetch the public IP automatically,
# ensure 'requests' is installed. Otherwise, we skip public IP.
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


ASCII_BANNER = r"""
      :::::::::       ::::::::::     :::       :::
     :+:    :+:      :+:            :+:       :+:
    +:+    +:+      +:+            +:+       +:+
   +#+    +:+      +#++:++#       +#+  +:+  +#+
  +#+    +#+      +#+            +#+ +#+#+ +#+
 #+#    #+#      #+#             #+#+# #+#+#    by Exfil0
#########   .   ##########   .   ###   ###   -  v1.1

~ Mapping Attack Surface - @HornetStrike and @ScaryByte ~
                 ~ DYNAMIC ENUM WIZARD ~
"""

# ------------------ GLOBAL CONFIG ------------------

REQUIRED_TOOLS = {
    "whois": "whois",
    "subfinder": "subfinder",
    "assetfinder": "assetfinder",
    "amass": "amass",
    "nmap": "nmap",
    "searchsploit": "exploitdb",
    "dig": "dnsutils",
    "dirb": "dirb",
    "naabu": "naabu",
    "gowitness": "gowitness",
    "theharvester": "theharvester",
    "emailharvester": "emailharvester",
    "recon-ng": "recon-ng"
}

SUBLIST3R_CMD     = "sublist3r"
SUBLIST3R_APT_PKG = "sublist3r"

SPINNER_CHARS  = ["<", ">", "*", "X"]
PROGRESS_LINES = []
stop_spinner   = False
use_concurrency= False
STEP_TIMINGS   = {}  # step_name -> (start_time, end_time)
start_time     = None

# We'll store a single-line environment reference for the spinner
ENV_LINE = ""  # Will be set in main() after we gather environment info.

# ------------------ LOGGING SETUP ------------------
# Configured in main() at the bottom.

# -------------- HELPER FUNCTIONS (Timing, Commands, Domain Check) --------------

def start_timing(step_name):
    STEP_TIMINGS[step_name] = [time.time(), None]

def end_timing(step_name):
    if step_name in STEP_TIMINGS and STEP_TIMINGS[step_name][1] is None:
        STEP_TIMINGS[step_name][1] = time.time()

def run_cmd(cmd_list, stdout_file=None):
    """
    Runs an external command. If stdout_file is provided, writes stdout/stderr to that file.
    Otherwise, discards the output to /dev/null.
    Logs warnings on non-zero return codes, and errors on exceptions.
    """
    import subprocess
    logging.debug(f"Running command: {' '.join(cmd_list)}")

    try:
        if stdout_file:
            with open(stdout_file, "w") as out:
                res = subprocess.run(cmd_list, stdout=out, stderr=out, check=False)
        else:
            res = subprocess.run(cmd_list, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        if res.returncode != 0:
            logging.warning(f"[run_cmd] Non-zero exit ({res.returncode}) => {' '.join(cmd_list)}")
    except Exception as e:
        logging.error(f"[run_cmd] Exception => {e}")

def ensure_timestamped_dir(domain):
    """
    Creates a directory like 'wizard_enum_<domain>_YYYYMMDD-HHMMSS'.
    Returns the path to that directory.
    """
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    dirname = f"wizard_enum_{domain}_{timestamp}"
    os.makedirs(dirname, exist_ok=True)
    return dirname

def is_valid_domain(candidate):
    candidate = candidate.strip().lower()
    if not candidate:
        return False
    # Exclude IP addresses
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", candidate):
        return False
    if re.match(r"^as\d+", candidate) or "asn" in candidate:
        return False
    return ('.' in candidate)

# -------------- CURSES UI & SPINNER --------------

def add_progress_line(stdscr, line, color_pair=1):
    PROGRESS_LINES.append((line, color_pair))
    redraw_screen(stdscr)

def redraw_screen(stdscr):
    stdscr.clear()
    height, width = stdscr.getmaxyx()
    max_log_lines = height - 1
    start_idx     = max(0, len(PROGRESS_LINES) - max_log_lines)
    visible_lines = PROGRESS_LINES[start_idx:]

    stdscr.attron(curses.color_pair(3))
    banner_lines = ASCII_BANNER.split("\n")
    row = 0
    for bline in banner_lines:
        if row >= max_log_lines:
            break
        stdscr.addstr(row, 0, bline[:width-1])
        row += 1
    stdscr.attroff(curses.color_pair(3))

    for (line_text, cpair) in visible_lines:
        if row >= max_log_lines:
            break
        stdscr.attron(curses.color_pair(cpair))
        stdscr.addstr(row, 0, line_text[:width-1])
        stdscr.attroff(curses.color_pair(cpair))
        row += 1

    stdscr.refresh()

def spinner_thread_func(stdscr):
    """
    Spinner thread that shows CPU/MEM usage (if psutil) and elapsed time since start_time,
    plus environment info (OS, hostname, public IP) near the timer.
    """
    global stop_spinner, ENV_LINE
    import time
    idx = 0
    while not stop_spinner:
        height, width = stdscr.getmaxyx()
        spin_char = SPINNER_CHARS[idx]
        idx = (idx + 1) % len(SPINNER_CHARS)

        usage_str = ""
        if PSUTIL_AVAILABLE:
            import psutil
            cpu_pct = psutil.cpu_percent()
            mem_pct = psutil.virtual_memory().percent
            usage_str = f" CPU:{cpu_pct:2.0f}% MEM:{mem_pct:2.0f}%"

        elapsed = time.time() - start_time
        hh = int(elapsed // 3600)
        mm = int((elapsed % 3600) // 60)
        ss = int(elapsed % 60)
        time_str = f"TIME:{hh:02d}:{mm:02d}:{ss:02d}"

        # ENV_LINE might look like: "OS: Linux Host: myhost IP: 1.2.3.4"
        msg = f"[ Mapping Attack Surface... {spin_char} ]{usage_str} {time_str} {ENV_LINE}"
        msg = msg[:width-1]  # Truncate if terminal is narrow

        stdscr.attron(curses.color_pair(4))
        spinner_row = height - 1
        stdscr.move(spinner_row, 0)
        stdscr.clrtoeol()
        stdscr.addstr(spinner_row, 0, msg)
        stdscr.attroff(curses.color_pair(4))
        stdscr.refresh()

        time.sleep(0.15)

    spinner_row = curses.LINES - 1
    stdscr.move(spinner_row, 0)
    stdscr.clrtoeol()
    stdscr.refresh()

# -------------- INSTALL & CHECK REQUIRED TOOLS --------------

def check_and_install_tools(stdscr):
    """
    Checks for required tools and attempts to install them if missing.
    Logs failures or successes.
    """
    import subprocess
    apt_updated = False
    for cmd, pkg in REQUIRED_TOOLS.items():
        if shutil.which(cmd) is None:
            add_progress_line(stdscr, f"[!] Installing '{cmd}' => '{pkg}'...", color_pair=2)
            logging.info(f"Attempting to install '{cmd}' => '{pkg}'...")
            if not apt_updated:
                subprocess.run(["apt-get", "update", "-y"], check=False)
                apt_updated = True

            res = subprocess.run(["apt-get", "install", "-y", pkg], check=False)
            if res.returncode != 0:
                add_progress_line(stdscr, f"[!] Attempting pip3 install for '{cmd}'...", color_pair=2)
                pip_res = subprocess.run(["pip3", "install", cmd.lower()], check=False)
                if pip_res.returncode != 0:
                    add_progress_line(stdscr, f"[-] Could not install '{cmd}'. Please install manually.", color_pair=2)
                    logging.error(f"Could not install '{cmd}'. Manual intervention required.")
                    return False

            if shutil.which(cmd) is None:
                add_progress_line(stdscr, f"[-] '{cmd}' not found after attempts.", color_pair=2)
                logging.error(f"'{cmd}' still not found after attempts.")
                return False
            else:
                add_progress_line(stdscr, f"[+] '{cmd}' installed OK.", color_pair=1)
                logging.info(f"'{cmd}' installed successfully.")
        else:
            logging.debug(f"'{cmd}' already installed.")

    # sublist3r specifically
    if shutil.which(SUBLIST3R_CMD) is None:
        add_progress_line(stdscr, "[!] Installing sublist3r...", color_pair=2)
        logging.info("Installing sublist3r...")
        if not apt_updated:
            subprocess.run(["apt-get", "update", "-y"], check=False)
            apt_updated = True

        res_subl = subprocess.run(["apt-get", "install", "-y", SUBLIST3R_APT_PKG], check=False)
        if res_subl.returncode != 0:
            add_progress_line(stdscr, "[!] Trying 'pip3 install sublist3r'...", color_pair=2)
            pip_res = subprocess.run(["pip3", "install", "sublist3r"], check=False)
            if pip_res.returncode != 0:
                add_progress_line(stdscr, "[-] Could not install sublist3r. Install manually.", color_pair=2)
                logging.error("Could not install sublist3r.")
                return False

        if shutil.which(SUBLIST3R_CMD) is None:
            add_progress_line(stdscr, "[-] sublist3r not found after attempts.", color_pair=2)
            logging.error("sublist3r not found after attempts.")
            return False
        else:
            add_progress_line(stdscr, "[+] sublist3r installed OK.", color_pair=1)
            logging.info("sublist3r installed successfully.")

    return True


# -------------- WHOIS LOOKUP --------------

def whois_lookup(stdscr, domain):
    """
    Perform whois on the domain and store output in logs/whois.txt.
    """
    add_progress_line(stdscr, "[WHOIS] Looking up domain registration info...")
    os.makedirs("logs", exist_ok=True)
    out_file = "logs/whois.txt"
    run_cmd(["whois", domain], stdout_file=out_file)
    add_progress_line(stdscr, f"[WHOIS] Output => {out_file}")
    logging.info(f"Whois info written to => {out_file}")


# -------------- SUBDOMAIN ENUM + DNS, SSL, EMAIL, PORTS, DIRB --------------

def subdomain_enumeration(stdscr, domain):
    add_progress_line(stdscr, f"[Subdomain] Enumerating => {domain}")
    os.makedirs("logs", exist_ok=True)
    subfinder_file    = "logs/subfinder.txt"
    assetfinder_file  = "logs/assetfinder_raw.txt"

    run_cmd(["subfinder", "-silent", "-d", domain, "-o", subfinder_file], stdout_file=subfinder_file)

    with open(assetfinder_file, "w") as af_out:
        import subprocess
        subprocess.run(["assetfinder", domain], stdout=af_out, stderr=af_out, check=False)

    assetfinder_filtered = "logs/assetfinder.txt"
    with open(assetfinder_file) as af_in, open(assetfinder_filtered, "w") as af_out:
        for line in af_in:
            line = line.strip()
            if domain in line:
                af_out.write(line + "\n")

    combined_set = set()
    for f in [subfinder_file, assetfinder_filtered]:
        if os.path.exists(f):
            with open(f) as fin:
                for line in fin:
                    subd = line.strip()
                    if subd:
                        combined_set.add(subd)

    subs_sorted = sorted(combined_set)
    merged_file = "all_subdomains_merged.txt"
    with open(merged_file, "w") as out:
        for s in subs_sorted:
            out.write(s + "\n")

    add_progress_line(stdscr, f"[Subdomain] Found {len(subs_sorted)} unique subdomains => {merged_file}")
    return subs_sorted

def dns_resolution(stdscr, subdomains):
    add_progress_line(stdscr, "[DNS] Resolving subdomains...")
    os.makedirs("logs/dns", exist_ok=True)
    dns_log_path = "logs/dns/dns_resolution.txt"
    resolved = []

    if use_concurrency:
        add_progress_line(stdscr, "[DNS] Running concurrency mode...")
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=10) as executor, open(dns_log_path, "w") as dns_log:
            futures = {}
            for sd in subdomains:
                futures[executor.submit(dig_subdomain, sd)] = sd

            for fut in as_completed(futures):
                sd = futures[fut]
                try:
                    ips = fut.result()
                    for ip in ips:
                        dns_log.write(f"{sd} => {ip}\n")
                        resolved.append((sd, ip))
                except Exception as e:
                    dns_log.write(f"{sd} => [ERROR] {e}\n")

    else:
        with open(dns_log_path, "w") as dns_log:
            for i, sd in enumerate(subdomains, start=1):
                add_progress_line(stdscr, f"[DNS] {i}/{len(subdomains)} => {sd}")
                ips = dig_subdomain(sd)
                for ip in ips:
                    dns_log.write(f"{sd} => {ip}\n")
                    resolved.append((sd, ip))

    add_progress_line(stdscr, f"[DNS] Resolved {len(resolved)} subdomain->IP combos.")
    return resolved

def dig_subdomain(sd):
    import subprocess
    ips = []
    cp = subprocess.run(["dig", "+short", "A", sd], capture_output=True, text=True)
    for line in cp.stdout.splitlines():
        line = line.strip()
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", line):
            ips.append(line)
    return ips

def ssl_check(stdscr, subdomains):
    add_progress_line(stdscr, "[SSL] Checking subdomains on port 443...")
    os.makedirs("logs/ssl", exist_ok=True)
    total = len(subdomains)
    for i, sd in enumerate(subdomains, start=1):
        add_progress_line(stdscr, f"[SSL] {i}/{total} => {sd}")
        out_file = f"logs/ssl/{sd.replace('/', '_')}.txt"
        cmd_ssl = [
            "openssl", "s_client",
            "-connect", f"{sd}:443",
            "-servername", sd,
            "-showcerts",
            "-verify", "2"
        ]
        run_cmd(cmd_ssl, stdout_file=out_file)

    add_progress_line(stdscr, "[SSL] Finished checking certificates.")

def gather_emails(stdscr, domain):
    add_progress_line(stdscr, "[EMAIL] Gathering from theHarvester, EmailHarvester, recon-ng...")
    os.makedirs("logs", exist_ok=True)
    all_emails = set()

    theharvester_file = f"logs/theharvester_{domain}.txt"
    cmd_theharvester  = ["theharvester", "-d", domain, "-b", "all", "-f", theharvester_file]
    add_progress_line(stdscr, f"[EMAIL] Running => {cmd_theharvester}")
    run_cmd(cmd_theharvester, stdout_file=theharvester_file)
    th_emails = parse_emails_from_file(theharvester_file)
    all_emails.update(th_emails)

    emailharvester_file = f"logs/emailharvester_{domain}.txt"
    cmd_emailharvester  = ["emailharvester", "-d", domain, "-l", "100"]
    add_progress_line(stdscr, f"[EMAIL] Running => {cmd_emailharvester}")
    run_cmd(cmd_emailharvester, stdout_file=emailharvester_file)
    eh_emails = parse_emails_from_file(emailharvester_file)
    all_emails.update(eh_emails)

    recon_file = f"logs/reconng_{domain}.txt"
    cmd_reconng = ["recon-ng", "--workspace", "default"]
    add_progress_line(stdscr, f"[EMAIL] Running => {cmd_reconng}")
    run_cmd(cmd_reconng, stdout_file=recon_file)
    rn_emails = parse_emails_from_file(recon_file)
    all_emails.update(rn_emails)

    merged = sorted(all_emails)
    outpath = "logs/emails_merged.txt"
    with open(outpath, "w") as out:
        for e in merged:
            out.write(e + "\n")

    add_progress_line(stdscr, f"[EMAIL] Found {len(merged)} unique emails => {outpath}")

def parse_emails_from_file(filepath):
    results = set()
    if os.path.exists(filepath):
        import re
        regex = re.compile(r"[a-zA-Z0-9.\-_+#~!$&',;=:]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]+")
        with open(filepath, "r", encoding="utf-8", errors="ignore") as fin:
            for line in fin:
                found = regex.findall(line)
                for item in found:
                    results.add(item.strip())
    return results

def port_scanning(stdscr, resolved_ips, port_label, nmap_flag):
    add_progress_line(stdscr, f"[Nmap] Scanning IPs => {port_label}")
    os.makedirs("nmap_scans", exist_ok=True)
    unique_ips = sorted({ip for (_, ip) in resolved_ips})

    for idx, ip in enumerate(unique_ips, start=1):
        add_progress_line(stdscr, f"[Nmap] {idx}/{len(unique_ips)} => {ip}")
        out_file = f"nmap_scans/{ip}.txt"
        cmd_nmap = ["nmap", "-sV", "-T4", ip, "-oN", out_file]
        if nmap_flag:
            cmd_nmap.insert(2, nmap_flag)
        run_cmd(cmd_nmap)

    add_progress_line(stdscr, "[Nmap] Completed scanning.")

def dirb_bruteforce(stdscr, subdomains, dirb_wordlist):
    add_progress_line(stdscr, f"[Dirb] Using wordlist => {dirb_wordlist}")
    os.makedirs("dirb_scans", exist_ok=True)
    wordlist_path = f"/usr/share/dirb/wordlists/{dirb_wordlist}.txt"

    total = len(subdomains)
    for i, sd in enumerate(subdomains, start=1):
        add_progress_line(stdscr, f"[Dirb] {i}/{total} => http://{sd}")
        out_http = f"dirb_scans/{sd}_http_{dirb_wordlist}.txt"
        cmd_http = ["dirb", f"http://{sd}/", wordlist_path, "-o", out_http]
        run_cmd(cmd_http)

        add_progress_line(stdscr, f"[Dirb] => https://{sd}")
        out_https = f"dirb_scans/{sd}_https_{dirb_wordlist}.txt"
        cmd_https = ["dirb", f"https://{sd}/", wordlist_path, "-o", out_https]
        run_cmd(cmd_https)

    add_progress_line(stdscr, "[Dirb] Completed brute-forcing subdomains.")


# -------------- DORKS (Optional Step) --------------

def gather_dorks(stdscr, domain):
    """
    Reads local 'dorks.txt' and replaces '{TARGET}' with the user's domain,
    then writes them to logs/dorks_output.txt for manual usage.
    """
    add_progress_line(stdscr, "[DORKS] Processing local dorks.txt...")

    local_dorks_file = "dorks.txt"
    if not os.path.exists(local_dorks_file):
        add_progress_line(stdscr, "[-] dorks.txt not found. Skipping dorking step.", color_pair=2)
        logging.warning("dorks.txt was not found in the current directory.")
        return

    os.makedirs("logs", exist_ok=True)
    out_file = "logs/dorks_output.txt"

    processed_lines = []
    with open(local_dorks_file, "r", encoding="utf-8") as fin:
        for line in fin:
            line = line.strip()
            if line:
                dork = line.replace("{TARGET}", domain)
                processed_lines.append(dork)

    with open(out_file, "w", encoding="utf-8") as fout:
        for dork_line in processed_lines:
            fout.write(dork_line + "\n")

    add_progress_line(stdscr, f"[DORKS] Wrote {len(processed_lines)} dorks => {out_file}")
    logging.info(f"Dorks generated into {out_file}.")


# -------------- GOWITNESS (Screenshots) --------------

def gowitness_screenshots(stdscr, subdomains):
    """
    Takes screenshots of each subdomain using GoWitness.
    """
    add_progress_line(stdscr, "[GoWitness] Taking screenshots of subdomains...")

    out_dir = "gowitness_shots"
    os.makedirs(out_dir, exist_ok=True)

    for idx, sd in enumerate(subdomains, start=1):
        add_progress_line(stdscr, f"[GoWitness] {idx}/{len(subdomains)} => {sd}")

        cmd_http  = ["gowitness", "single", "--timeout", "10",
                     "--destination", out_dir, "--url", f"http://{sd}"]
        cmd_https = ["gowitness", "single", "--timeout", "10",
                     "--destination", out_dir, "--url", f"https://{sd}"]

        run_cmd(cmd_http)
        run_cmd(cmd_https)

    add_progress_line(stdscr, "[GoWitness] Screenshots complete.")


# -------------- SEARCHSPLOIT (Based on Nmap Services) --------------

def searchsploit_exploits(stdscr, nmap_scan_dir):
    """
    Parse the nmap_scans/*.txt for services, run searchsploit <service>.
    Writes results to logs/searchsploit_results.txt.
    """
    add_progress_line(stdscr, "[SearchSploit] Checking enumerated services for exploits...")

    os.makedirs("logs", exist_ok=True)
    out_file = "logs/searchsploit_results.txt"

    if not os.path.isdir(nmap_scan_dir):
        add_progress_line(stdscr, f"[-] Nmap scans directory not found: {nmap_scan_dir}", color_pair=2)
        logging.warning(f"Nmap scan directory missing => {nmap_scan_dir}")
        return

    service_line_regex = re.compile(r"^\d+/tcp\s+open\s+([^\s]+)\s+(.*)", re.IGNORECASE)
    discovered_services = set()

    for fname in os.listdir(nmap_scan_dir):
        if not fname.endswith(".txt"):
            continue
        full_path = os.path.join(nmap_scan_dir, fname)
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                match = service_line_regex.match(line)
                if match:
                    raw_service = match.group(2)  # e.g. "Apache httpd 2.4.7"
                    if raw_service:
                        discovered_services.add(raw_service)

    with open(out_file, "w", encoding="utf-8") as out:
        import subprocess
        for service in discovered_services:
            out.write(f"===== Searchsploit results for: {service} =====\n")
            cmd = ["searchsploit", service]
            res = subprocess.run(cmd, capture_output=True, text=True)
            out.write(res.stdout)
            out.write("\n\n")

    add_progress_line(stdscr, f"[SearchSploit] Results => {out_file}")
    logging.info(f"Searchsploit results stored in {out_file}.")


# -------------- CONSOLIDATED JSON/CSV REPORT --------------

def create_consolidated_report(domain, subdomains, resolved_ips, outdir):
    """
    Creates a JSON and CSV file in 'outdir' summarizing discovered subdomains & IP combos.
    """
    data = {
        "domain": domain,
        "num_subdomains": len(subdomains),
        "subdomains": subdomains,
        "resolved_ips": [{"subdomain": sd, "ip": ip} for (sd, ip) in resolved_ips],
        "timestamp": time.time()
    }

    json_path = os.path.join(outdir, "consolidated_report.json")
    csv_path  = os.path.join(outdir, "resolved_ips.csv")

    # JSON
    try:
        with open(json_path, "w", encoding="utf-8") as jout:
            json.dump(data, jout, indent=2)
        logging.info(f"[REPORT] JSON => {json_path}")
    except Exception as e:
        logging.error(f"Failed writing JSON => {e}")

    # CSV
    try:
        with open(csv_path, "w", newline="", encoding="utf-8") as cfile:
            writer = csv.writer(cfile)
            writer.writerow(["Subdomain", "IP"])
            for sd, ip in resolved_ips:
                writer.writerow([sd, ip])
        logging.info(f"[REPORT] CSV => {csv_path}")
    except Exception as e:
        logging.error(f"Failed writing CSV => {e}")


# -------------- MAIN ENUM FLOW --------------

def enumeration_flow(stdscr, domain, amass_brute, sublister_ports, amass_ports, nmap_flag, port_label, dirb_wordlist):
    start_timing("CheckInstall")
    add_progress_line(stdscr, "[+] Checking/Installing required tools...")
    if not check_and_install_tools(stdscr):
        end_timing("CheckInstall")
        add_progress_line(stdscr, "[-] Missing tools, cannot continue.", color_pair=2)
        return
    end_timing("CheckInstall")

    # 1) Create timestamped workspace
    start_timing("WorkspaceSetup")
    workdir = ensure_timestamped_dir(domain)
    try:
        os.chdir(workdir)
    except Exception as e:
        add_progress_line(stdscr, f"[-] Could not enter {workdir}: {e}", color_pair=2)
        end_timing("WorkspaceSetup")
        return
    os.makedirs("logs", exist_ok=True)
    add_progress_line(stdscr, f"[+] Workspace: {os.getcwd()}")
    end_timing("WorkspaceSetup")

    # 2) WHOIS
    start_timing("WHOIS")
    whois_lookup(stdscr, domain)
    end_timing("WHOIS")

    # 3) Subdomain enumeration
    start_timing("SubdomainEnum")
    subdomains = subdomain_enumeration(stdscr, domain)
    end_timing("SubdomainEnum")

    # 4) DNS checks
    start_timing("DNSResolution")
    subdomain_ips = dns_resolution(stdscr, subdomains)
    end_timing("DNSResolution")

    # 5) SSL checks
    start_timing("SSLChecks")
    ssl_check(stdscr, subdomains)
    end_timing("SSLChecks")

    # 6) Email Gathering
    start_timing("EmailGathering")
    gather_emails(stdscr, domain)
    end_timing("EmailGathering")

    # 7) Port scanning
    start_timing("PortScan")
    port_scanning(stdscr, subdomain_ips, port_label, nmap_flag)
    end_timing("PortScan")

    # 8) Dirb brute-forcing
    start_timing("Dirb")
    dirb_bruteforce(stdscr, subdomains, dirb_wordlist)
    end_timing("Dirb")

    # 9) Dorks
    start_timing("Dorks")
    gather_dorks(stdscr, domain)
    end_timing("Dorks")

    # 10) GoWitness screenshots
    start_timing("GoWitness")
    gowitness_screenshots(stdscr, subdomains)
    end_timing("GoWitness")

    # 11) Searchsploit based on Nmap results
    start_timing("SearchSploit")
    searchsploit_exploits(stdscr, "nmap_scans")
    end_timing("SearchSploit")

    # 12) Consolidated JSON/CSV
    start_timing("Report")
    create_consolidated_report(domain, subdomains, subdomain_ips, os.getcwd())
    end_timing("Report")

    add_progress_line(stdscr, "[+] Completed Full Enumeration Flow!")


# -------------- TIMELINE + ENVIRONMENT REFERENCES --------------

def build_ascii_timeline(timings_dict):
    completed_steps = []
    for k, (start_ts, end_ts) in timings_dict.items():
        if end_ts is not None:
            dur = end_ts - start_ts
            completed_steps.append((k, dur))

    if not completed_steps:
        return "No timeline data available."

    longest = max(x[1] for x in completed_steps)
    scale   = 40.0 / longest
    lines   = []
    lines.append("----- Execution Timeline -----")
    for (step_name, dur) in sorted(completed_steps, key=lambda x: x[1], reverse=True):
        bar_len = int(dur * scale)
        bar     = "#" * bar_len
        lines.append(f"{step_name:15s}: [{bar}] {dur:.2f}s")
    return "\n".join(lines)

def gather_environment_info():
    """
    Gather references about the scanning machine:
      - OS & version
      - Hostname
      - Private/Internal IP
      - Public IP (if 'requests' is installed)
    """
    info_lines = []

    # OS & version
    os_version = platform.platform()
    info_lines.append(os_version)

    # Hostname
    hostname = socket.gethostname()
    info_lines.append(hostname)

    # Internal/Private IP
    try:
        internal_ip = socket.gethostbyname(hostname)
    except:
        internal_ip = "N/A"

    # Public IP
    public_ip = "N/A"
    if REQUESTS_AVAILABLE:
        try:
            public_ip = requests.get("https://api.ipify.org").text.strip()
        except:
            public_ip = "N/A"

    # Return them as a single line so we can put it near the timer
    return (os_version, hostname, public_ip)


# -------------- CURSES MAIN --------------

def curses_main(stdscr, domain, amass_brute, sublister_ports, amass_ports, nmap_flag, port_label, dirb_wordlist):
    import curses
    curses.start_color()
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_CYAN, curses.COLOR_BLACK)
    curses.init_pair(4, curses.COLOR_MAGENTA, curses.COLOR_BLACK)

    stdscr.clear()
    stdscr.refresh()

    spinner_thr = threading.Thread(target=spinner_thread_func, args=(stdscr,), daemon=True)
    spinner_thr.start()

    enumeration_flow(stdscr, domain, amass_brute, sublister_ports, amass_ports, nmap_flag, port_label, dirb_wordlist)

    global stop_spinner
    stop_spinner = True
    spinner_thr.join()

    # Display the ASCII timeline at the bottom
    timeline_str = build_ascii_timeline(STEP_TIMINGS)
    for line in timeline_str.split("\n"):
        add_progress_line(stdscr, line, color_pair=1)

    add_progress_line(stdscr, "[+] Press any key to exit the Recon Wizard...", color_pair=1)
    stdscr.getch()


# -------------- MAIN --------------

def main():
    # Setup logging
    logging.basicConfig(
        filename="recon_wizard.log",
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    if os.geteuid() != 0:
        print("[-] Please run as sudo to allow auto-install of missing packages.")
        logging.error("Not running as root/sudo. Exiting.")
        sys.exit(1)

    global start_time
    start_time = time.time()

    print(ASCII_BANNER)
    print("[*] Loading Complete Recon Wizard...\n")

    if not PSUTIL_AVAILABLE:
        print("[!] psutil is not installed => no CPU/MEM usage in spinner.\n")
        logging.warning("psutil not found, spinner CPU/MEM usage disabled.")

    # Gather user inputs
    domain = input("[?] Target domain (e.g., example.com): ").strip()
    if not domain:
        print("[-] No domain provided. Exiting.")
        logging.error("No domain provided. Exiting.")
        sys.exit(1)

    brute_in = input("[?] Enable AMASS brute force? (y/N): ").lower().strip()
    amass_brute = (brute_in == "y")

    print("\nPort scanning approach (for Nmap, sublist3r, amass):")
    print("  1) Common HTTP/HTTPS only (80,443)")
    print("  2) Extended Common Ports => top 1000")
    print("  3) All 65535 TCP ports")
    port_choice = input("[?] Enter 1, 2, or 3: ").strip()

    sublister_ports = ""
    amass_ports     = ""
    nmap_flag       = ""
    port_label      = ""

    if port_choice == "3":
        sublister_ports = "1-65535"
        amass_ports     = "1-65535"
        nmap_flag       = "-p-"
        port_label      = "All 65535 TCP Ports"
    elif port_choice == "2":
        port_label      = "Top 1000 Ports"
    else:
        sublister_ports = "80,443"
        amass_ports     = "80,443"
        nmap_flag       = "-p80,443"
        port_label      = "Common HTTP/HTTPS (80,443)"

    print("\nDirectory brute-force wordlist options:")
    print("   1) common.txt")
    print("   2) big.txt")
    dirb_choice = input("[?] Choose 1 or 2: ").strip()
    if dirb_choice == "2":
        dirb_wordlist = "big"
    else:
        dirb_wordlist = "common"

    global use_concurrency
    concurrency_choice = input("\n[?] Enable concurrency for DNS, Dirb, GoWitness, Naabu? (y/N): ").lower().strip()
    use_concurrency = (concurrency_choice == "y")

    # Gather environment info => single line for spinner
    os_ver, hostnm, pubip = gather_environment_info()
    # e.g. "OS: Linux Host: myhost IP: 1.2.3.4"
    global ENV_LINE
    ENV_LINE = f"OS:{os_ver} Host:{hostnm} IP:{pubip}"

    import curses
    try:
        curses.wrapper(
            curses_main,
            domain,
            amass_brute,
            sublister_ports,
            amass_ports,
            nmap_flag,
            port_label,
            dirb_wordlist
        )
    except KeyboardInterrupt:
        logging.warning("User interrupted execution with Ctrl+C.")
        print("\n[-] Script interrupted by user.")
        sys.exit(1)

    # The script is done => references at the bottom:
    print("\n[+] Script finished. Output was saved to a timestamped workspace.")
    print("[+] Merged email results => logs/emails_merged.txt (deduplicated).")
    print("[+] The ASCII timeline was shown in curses at the end!\n")

    # Environment references (long form):
    print("----- Environment References -----")
    print(f"  OS Version : {os_ver}")
    print(f"  Hostname   : {hostnm}")
    print(f"  Public IP  : {pubip}")
    print("----------------------------------\n")


if __name__ == "__main__":
    main()
