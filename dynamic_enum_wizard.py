#!/usr/bin/env python3

import os
import re
import sys
import time
import shutil
import curses
import threading
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import psutil  # For CPU & MEM usage
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

ASCII_BANNER = r"""
      :::::::::       ::::::::::     :::       ::: 
     :+:    :+:      :+:            :+:       :+:  
    +:+    +:+      +:+            +:+       +:+   
   +#+    +:+      +#++:++#       +#+  +:+  +#+    
  +#+    +#+      +#+            +#+ +#+#+ +#+     
 #+#    #+#      #+#             #+#+# #+#+#    Exfil0   
#########       ##########       ###   ###      v1.0   

      ~ Mapping the Attack Surface for Maximum Exploitation ~
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
    "gowitness": "gowitness"
}

SUBLIST3R_CMD = "sublist3r"
SUBLIST3R_APT_PKG = "sublist3r"

SPINNER_CHARS = ["<", ">", "*", "X"]
PROGRESS_LINES = []
stop_spinner = False  # Controls the spinner thread
use_concurrency = False

# We'll store step timings in a dictionary: step_name -> (start_time, end_time)
STEP_TIMINGS = {}

def start_timing(step_name):
    """Mark the start time of a major step."""
    STEP_TIMINGS[step_name] = [time.time(), None]

def end_timing(step_name):
    """Mark the end time of a major step."""
    if step_name in STEP_TIMINGS and STEP_TIMINGS[step_name][1] is None:
        STEP_TIMINGS[step_name][1] = time.time()

# --------------- HELPER FUNCTIONS ------------------

def run_cmd(cmd_list, stdout_file=None):
    """
    Runs a command. If stdout_file is given, logs STDOUT/ERR there,
    else discards them quietly for minimal terminal spam.
    """
    if stdout_file:
        with open(stdout_file, "w") as out:
            subprocess.run(cmd_list, stdout=out, stderr=out, check=False)
    else:
        subprocess.run(cmd_list, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

def is_valid_domain(candidate):
    """Returns True if 'candidate' looks like a valid domain (FQDN)."""
    candidate = candidate.strip().lower()
    if not candidate:
        return False
    # Exclude pure IPv4 addresses
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", candidate):
        return False
    # Exclude ASN-like
    if re.match(r"^as\d+", candidate):
        return False
    if "asn" in candidate:
        return False
    return ('.' in candidate)

# ------------------ CURSES UI + COLOR ------------------

def add_progress_line(stdscr, line, color_pair=1):
    """
    Adds a short line to PROGRESS_LINES, then redraws the curses screen with color.
    """
    PROGRESS_LINES.append((line, color_pair))
    redraw_screen(stdscr)

def redraw_screen(stdscr):
    """Redraw the screen with progress lines, leaving bottom row for spinner."""
    stdscr.clear()
    height, width = stdscr.getmaxyx()

    max_log_lines = height - 1  # last line is for spinner
    start_idx = max(0, len(PROGRESS_LINES) - max_log_lines)
    visible_lines = PROGRESS_LINES[start_idx:]

    # Print ASCII banner at the top in color
    stdscr.attron(curses.color_pair(3))  # color pair for banner
    banner_lines = ASCII_BANNER.split("\n")
    row = 0
    for bline in banner_lines:
        if row >= max_log_lines:
            break
        stdscr.addstr(row, 0, bline[:width-1])
        row += 1
    stdscr.attroff(curses.color_pair(3))

    # Then print progress lines below banner
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
    Spinner in bottom row that also shows CPU/MEM usage if psutil is available.
    e.g. "[ Mapping Attack Surface... < ] CPU:40% MEM:30%"
    """
    global stop_spinner
    idx = 0
    while not stop_spinner:
        height, width = stdscr.getmaxyx()
        spinner_row = height - 1
        spin_char = SPINNER_CHARS[idx]
        idx = (idx + 1) % len(SPINNER_CHARS)

        usage_str = ""
        if PSUTIL_AVAILABLE:
            cpu_pct = psutil.cpu_percent()
            mem_pct = psutil.virtual_memory().percent
            usage_str = f" CPU:{cpu_pct:2.0f}% MEM:{mem_pct:2.0f}%"

        msg = f"[ Mapping Attack Surface... {spin_char} ]{usage_str}"
        msg = msg[:width-1]  # truncate if too wide

        stdscr.attron(curses.color_pair(4))
        stdscr.move(spinner_row, 0)
        stdscr.clrtoeol()
        stdscr.addstr(spinner_row, 0, msg)
        stdscr.attroff(curses.color_pair(4))
        stdscr.refresh()

        time.sleep(0.15)

    # Clear spinner row
    spinner_row = curses.LINES - 1
    stdscr.move(spinner_row, 0)
    stdscr.clrtoeol()
    stdscr.refresh()

# ------------------ INSTALL & CHECK TOOLS ------------------

def check_and_install_tools(stdscr):
    """
    Checks if required tools exist, attempts apt-get or pip3 if not found.
    """
    apt_updated = False
    for cmd, pkg in REQUIRED_TOOLS.items():
        if shutil.which(cmd) is None:
            add_progress_line(stdscr, f"[!] Installing '{cmd}' => '{pkg}'...", color_pair=2)
            if not apt_updated:
                subprocess.run(["apt-get", "update", "-y"], check=False)
                apt_updated = True

            res = subprocess.run(["apt-get", "install", "-y", pkg], check=False)
            if res.returncode != 0:
                # fallback to pip
                add_progress_line(stdscr, f"[!] Attempting pip3 install for '{cmd}'...", color_pair=2)
                pip_res = subprocess.run(["pip3", "install", cmd.lower()], check=False)
                if pip_res.returncode != 0:
                    add_progress_line(stdscr, f"[-] Could not install '{cmd}'. Please install manually.", color_pair=2)
                    return False

            if shutil.which(cmd) is None:
                add_progress_line(stdscr, f"[-] '{cmd}' not found after attempts.", color_pair=2)
                return False
            else:
                add_progress_line(stdscr, f"[+] '{cmd}' installed OK.", color_pair=1)

    # sublist3r specifically
    if shutil.which(SUBLIST3R_CMD) is None:
        add_progress_line(stdscr, "[!] Installing sublist3r...", color_pair=2)
        if not apt_updated:
            subprocess.run(["apt-get", "update", "-y"], check=False)
            apt_updated = True

        subl_res = subprocess.run(["apt-get", "install", "-y", SUBLIST3R_APT_PKG], check=False)
        if subl_res.returncode != 0:
            add_progress_line(stdscr, "[!] Trying 'pip3 install sublist3r'...", color_pair=2)
            pip_res = subprocess.run(["pip3", "install", "sublist3r"], check=False)
            if pip_res.returncode != 0:
                add_progress_line(stdscr, "[-] Could not install sublist3r via apt or pip.", color_pair=2)
                return False

        if shutil.which(SUBLIST3R_CMD) is None:
            add_progress_line(stdscr, "[-] sublist3r not found after attempts.", color_pair=2)
            return False
        else:
            add_progress_line(stdscr, "[+] sublist3r installed OK.", color_pair=1)

    return True

# ------------------ CONCURRENCY TASK FUNCTIONS ------------------

def resolve_subdomain(sd):
    """Resolve a single subdomain with 'dig' (A record). Returns (sd, [ips])."""
    ip_list = []
    cp = subprocess.run(["dig", "+short", "A", sd], capture_output=True, text=True)
    for line in cp.stdout.splitlines():
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", line.strip()):
            ip_list.append(line.strip())
    return (sd, ip_list)

def run_dirb(sd, wordlist_path, output_dir):
    """Runs Dirb for HTTP and HTTPS on a single subdomain."""
    out_http = os.path.join(output_dir, f"{sd}_http.txt")
    out_https = os.path.join(output_dir, f"{sd}_https.txt")

    cmd_http = ["dirb", f"http://{sd}/", wordlist_path, "-o", out_http]
    subprocess.run(cmd_http, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    cmd_https = ["dirb", f"https://{sd}/", wordlist_path, "-o", out_https]
    subprocess.run(cmd_https, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

def run_gowitness(sd, gowitness_dir):
    """Run GoWitness to capture a screenshot for a single subdomain (HTTP & HTTPS)."""
    out_dir = os.path.join(gowitness_dir, sd.replace("/", "_"))
    os.makedirs(out_dir, exist_ok=True)

    # GoWitness single mode for HTTP
    cmd_gw_http = [
        "gowitness", "single",
        "--url", f"http://{sd}",
        "--destination", os.path.join(out_dir, "http.png"),
    ]
    subprocess.run(cmd_gw_http, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    # GoWitness single mode for HTTPS
    cmd_gw_https = [
        "gowitness", "single",
        "--url", f"https://{sd}",
        "--destination", os.path.join(out_dir, "https.png"),
    ]
    subprocess.run(cmd_gw_https, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

def run_naabu(ip, output_dir):
    """Runs Naabu on a single IP to discover open ports quickly."""
    out_file = os.path.join(output_dir, f"{ip}_naabu.txt")
    cmd_naabu = ["naabu", "-host", ip, "-o", out_file, "-silent"]
    subprocess.run(cmd_naabu, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

# ------------------ ENUMERATION FLOW ------------------

def enumeration_flow(stdscr, domain, amass_brute, sublister_ports, amass_ports, nmap_flag, port_label, dirb_wordlist):
    global use_concurrency

    # ---- Check Tools ----
    start_timing("CheckInstall")
    add_progress_line(stdscr, "[+] Checking/Installing required tools...")
    if not check_and_install_tools(stdscr):
        end_timing("CheckInstall")
        add_progress_line(stdscr, "[-] Missing tools, cannot continue.", color_pair=2)
        return
    end_timing("CheckInstall")

    # ---- Prepare workspace ----
    start_timing("WorkspaceSetup")
    workdir = f"wizard_enum_{domain}"
    os.makedirs(workdir, exist_ok=True)
    try:
        os.chdir(workdir)
    except Exception as e:
        add_progress_line(stdscr, f"[-] Could not enter {workdir}: {e}", color_pair=2)
        end_timing("WorkspaceSetup")
        return

    add_progress_line(stdscr, f"[+] Workspace: {os.getcwd()}")
    os.makedirs("logs", exist_ok=True)
    end_timing("WorkspaceSetup")

    # ---- WHOIS ----
    start_timing("WHOIS")
    add_progress_line(stdscr, "[WHOIS] Querying domain info...")
    run_cmd(["whois", domain], stdout_file="logs/whois_domain.txt")
    end_timing("WHOIS")

    # ---- Subdomain enumeration ----
    start_timing("SubdomainEnum")
    add_progress_line(stdscr, "[subfinder] scanning subdomains...")
    run_cmd(["subfinder", "-silent", "-d", domain, "-o", "logs/subfinder.txt"],
            stdout_file="logs/subfinder_log.txt")

    add_progress_line(stdscr, "[assetfinder] scanning subdomains...")
    with open("logs/assetfinder_log.txt", "w") as af_out:
        subprocess.run(["assetfinder", domain], stdout=af_out, stderr=af_out, check=False)
    with open("logs/assetfinder_log.txt") as af_in, open("logs/assetfinder.txt", "w") as af_f:
        for line in af_in:
            if domain in line:
                af_f.write(line)

    sublist_cmd = [SUBLIST3R_CMD, "-d", domain, "-o", "logs/sublist3r.txt"]
    if sublister_ports:
        sublist_cmd += ["-p", sublister_ports]
    add_progress_line(stdscr, "[sublist3r] scanning subdomains...")
    run_cmd(sublist_cmd, stdout_file="logs/sublist3r_log.txt")

    add_progress_line(stdscr, "[amass] passive enumeration...")
    run_cmd(["amass", "enum", "-passive", "-d", domain, "-o", "logs/amass_passive.txt"],
            stdout_file="logs/amass_passive_log.txt")

    # amass active
    amass_active_cmd = ["amass", "enum", "-active", "-d", domain]
    if amass_ports:
        amass_active_cmd += ["-p", amass_ports]
    out_file = "logs/amass_active.txt"
    if amass_brute:
        amass_active_cmd += ["-brute", "-w", "/usr/share/wordlists/dirb/common.txt"]
        out_file = "logs/amass_active_brute.txt"
        add_progress_line(stdscr, "[amass] active + brute scanning...")
    else:
        add_progress_line(stdscr, "[amass] active (no brute) scanning...")
    amass_active_cmd += ["-o", out_file]
    run_cmd(amass_active_cmd, stdout_file="logs/amass_active_log.txt")

    add_progress_line(stdscr, "[+] Merging subdomain outputs...")
    with open("all_subdomains_raw.txt", "w") as merged_out:
        for sf in [
            "subfinder.txt",
            "assetfinder.txt",
            "sublist3r.txt",
            "amass_passive.txt",
            "amass_active.txt",
            "amass_active_brute.txt"
        ]:
            pathf = os.path.join("logs", sf)
            if os.path.exists(pathf):
                with open(pathf, "r") as f_in:
                    merged_out.write(f_in.read())

    add_progress_line(stdscr, "[+] Filtering out junk subdomain lines...")
    filtered = set()
    with open("all_subdomains_raw.txt", "r") as raw_in:
        for line in raw_in:
            if is_valid_domain(line):
                filtered.add(line.strip())

    subdomains_merged = sorted(filtered)
    with open("all_subdomains_merged.txt", "w") as final_out:
        for sd in subdomains_merged:
            final_out.write(sd + "\n")

    add_progress_line(stdscr, f"[+] Found {len(subdomains_merged)} valid subdomains total.")
    end_timing("SubdomainEnum")

    # ---- DNS Resolution ----
    start_timing("DNS")
    add_progress_line(stdscr, "[DNS] Resolving subdomains...")
    os.makedirs("logs/dns", exist_ok=True)
    dns_log_path = "logs/dns/dns_resolution.txt"
    ipset = set()
    resolved_count = 0

    if use_concurrency:
        add_progress_line(stdscr, "[DNS] Running in concurrent mode...")
        with ThreadPoolExecutor(max_workers=10) as executor, open(dns_log_path, "w") as dns_log:
            future_to_sd = {executor.submit(resolve_subdomain, sd): sd for sd in subdomains_merged}
            for future in as_completed(future_to_sd):
                sd = future_to_sd[future]
                try:
                    subd, ips = future.result()
                    for ip in ips:
                        dns_log.write(f"{subd} -> {ip}\n")
                        ipset.add(ip)
                        resolved_count += 1
                except Exception as e:
                    dns_log.write(f"{sd} -> [ERROR] {e}\n")
    else:
        with open(dns_log_path, "w") as dns_log:
            for i, sd in enumerate(subdomains_merged, start=1):
                add_progress_line(stdscr, f"[DNS] {i}/{len(subdomains_merged)} subdomains...")
                subd, ips = resolve_subdomain(sd)
                for ip in ips:
                    dns_log.write(f"{subd} -> {ip}\n")
                    ipset.add(ip)
                    resolved_count += 1

    add_progress_line(stdscr, f"[DNS] Resolved {resolved_count} total subdomain->IP combos.")
    iplist = sorted(ipset)
    with open("all_ips_uniq.txt", "w") as f_ips:
        for ip in iplist:
            f_ips.write(ip + "\n")
    add_progress_line(stdscr, f"[DNS] Unique IPs found: {len(iplist)}")
    end_timing("DNS")

    # ---- SSL checks ----
    start_timing("SSL")
    add_progress_line(stdscr, "[SSL] Checking port 443 on subdomains...")
    os.makedirs("ssl_certs", exist_ok=True)
    for idx, sd in enumerate(subdomains_merged, start=1):
        add_progress_line(stdscr, f"[SSL] {idx}/{len(subdomains_merged)}...")
        out_file = os.path.join("ssl_certs", f"{sd.replace('/', '_')}_cert.txt")
        cmd_ssl = [
            "openssl", "s_client",
            "-connect", f"{sd}:443",
            "-servername", sd,
            "-showcerts",
            "-verify", "2",
        ]
        run_cmd(cmd_ssl, stdout_file=out_file)

    add_progress_line(stdscr, "[SSL] Cert data -> ssl_certs/")
    end_timing("SSL")

    # ---- Naabu scanning ----
    start_timing("Naabu")
    add_progress_line(stdscr, "[Naabu] Quick port scanning IPs...")
    os.makedirs("logs/naabu", exist_ok=True)

    def naabu_task(ip):
        run_naabu(ip, "logs/naabu")

    if use_concurrency:
        add_progress_line(stdscr, "[Naabu] Running in concurrent mode...")
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(naabu_task, ip) for ip in iplist]
            for _ in as_completed(futures):
                pass
    else:
        for i, ip in enumerate(iplist, start=1):
            add_progress_line(stdscr, f"[Naabu] {i}/{len(iplist)} => {ip}")
            naabu_task(ip)
    add_progress_line(stdscr, "[Naabu] Done => logs/naabu/")
    end_timing("Naabu")

    # ---- Nmap scanning ----
    start_timing("Nmap")
    add_progress_line(stdscr, f"[Nmap] scanning {len(iplist)} IPs => {port_label}")
    os.makedirs("nmap_scans", exist_ok=True)
    for idx, ip in enumerate(iplist, start=1):
        add_progress_line(stdscr, f"[Nmap] {idx}/{len(iplist)} => {ip}")
        out_file = f"nmap_scans/{ip}.txt"
        cmd_nmap = ["nmap", "-sV", "-T4", ip, "-oN", out_file]
        if nmap_flag:
            cmd_nmap.insert(2, nmap_flag)
        subprocess.run(cmd_nmap, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    add_progress_line(stdscr, "[Nmap] Completed. See nmap_scans/")
    end_timing("Nmap")

    # ---- Dirb scanning ----
    start_timing("Dirb")
    add_progress_line(stdscr, f"[Dirb] Brute forcing {len(subdomains_merged)} subdomains with {dirb_wordlist}.txt")
    os.makedirs("dirb_scans", exist_ok=True)
    wordlist_path = f"/usr/share/dirb/wordlists/{dirb_wordlist}.txt"

    if use_concurrency:
        add_progress_line(stdscr, "[Dirb] Running in concurrent mode...")
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for sd in subdomains_merged:
                futures.append(executor.submit(run_dirb, sd, wordlist_path, "dirb_scans"))
            for _ in as_completed(futures):
                pass
    else:
        for i, sd in enumerate(subdomains_merged, start=1):
            add_progress_line(stdscr, f"[Dirb] {i}/{len(subdomains_merged)} => {sd}")
            run_dirb(sd, wordlist_path, "dirb_scans")

    add_progress_line(stdscr, "[Dirb] Done. See dirb_scans/")
    end_timing("Dirb")

    # ---- GoWitness (screenshots) ----
    start_timing("GoWitness")
    add_progress_line(stdscr, "[GoWitness] Capturing screenshots of subdomains...")
    gowitness_dir = "gowitness_shots"
    os.makedirs(gowitness_dir, exist_ok=True)

    if use_concurrency:
        add_progress_line(stdscr, "[GoWitness] Running in concurrent mode...")
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for sd in subdomains_merged:
                futures.append(executor.submit(run_gowitness, sd, gowitness_dir))
            for _ in as_completed(futures):
                pass
    else:
        for i, sd in enumerate(subdomains_merged, start=1):
            add_progress_line(stdscr, f"[GoWitness] {i}/{len(subdomains_merged)} => {sd}")
            run_gowitness(sd, gowitness_dir)

    add_progress_line(stdscr, "[GoWitness] Done. See gowitness_shots/")
    end_timing("GoWitness")

    # ---- searchsploit ----
    start_timing("Searchsploit")
    add_progress_line(stdscr, "[Searchsploit] Checking Nmap service versions for known exploits...")
    os.makedirs("exploits", exist_ok=True)
    nm_files = [f for f in os.listdir("nmap_scans") if f.endswith(".txt")]
    for idx, fn in enumerate(nm_files, start=1):
        ipbase = fn.replace(".txt", "")
        add_progress_line(stdscr, f"[Searchsploit] {idx}/{len(nm_files)} => {ipbase}")
        path_in = os.path.join("nmap_scans", fn)
        path_out = os.path.join("exploits", f"{ipbase}_exploits.txt")

        with open(path_in, "r") as nin, open(path_out, "w") as eout:
            for line in nin:
                if re.match(r"^[0-9]+/tcp\s+open", line):
                    parts = line.split()
                    if len(parts) > 3:
                        svc_version = " ".join(parts[3:])
                        eout.write(f"[Service] {svc_version}\n")
                        so = subprocess.run(["searchsploit", svc_version],
                                            capture_output=True, text=True)
                        eout.write(so.stdout + "\n")
                        eout.write("---------------------------\n")

    add_progress_line(stdscr, "[Searchsploit] Completed. See exploits/")
    end_timing("Searchsploit")

    # ---- Final summary with timeline ----
    add_progress_line(stdscr, "========== Final Summary ==========", color_pair=3)
    add_progress_line(stdscr, f"Domain: {domain}", color_pair=3)
    add_progress_line(stdscr, f"AMASS Brute: {'Enabled' if amass_brute else 'Disabled'}", color_pair=3)
    add_progress_line(stdscr, f"Port Option: {port_label}", color_pair=3)
    add_progress_line(stdscr, f"Dirb Wordlist: {dirb_wordlist}.txt", color_pair=3)
    add_progress_line(stdscr, f"Concurrency: {'Enabled' if use_concurrency else 'Disabled'}", color_pair=3)
    add_progress_line(stdscr, "===================================", color_pair=3)

    # Generate an ASCII timeline of major steps
    # We'll measure each step's duration and produce bars. 
    timeline_str = build_ascii_timeline(STEP_TIMINGS)
    for line in timeline_str.split("\n"):
        add_progress_line(stdscr, line, color_pair=1)

    add_progress_line(stdscr, "[+] Attack surface mapped. Returning to shell...", color_pair=1)


# --------------- ASCII Timeline Function ----------------

def build_ascii_timeline(timings_dict):
    """
    Given a dict step_name -> [start, end],
    produce a multi-line ASCII timeline:
      StepName: [######] 3.5s
    """

    # We'll skip steps that never ended
    completed_steps = []
    for k, (start, end) in timings_dict.items():
        if end is not None:
            duration = end - start
            completed_steps.append((k, duration))
    if not completed_steps:
        return "No timeline data available."

    # Find the longest duration
    longest = max(x[1] for x in completed_steps)
    scale = 40.0 / longest  # We'll make the longest step ~40 chars

    lines = []
    lines.append("----- Execution Timeline -----")
    for (step_name, dur) in sorted(completed_steps, key=lambda x: x[1], reverse=True):
        bar_len = int(dur * scale)
        bar = "#" * bar_len
        lines.append(f"{step_name:15s}: [{bar}] {dur:.2f}s")

    return "\n".join(lines)

# ------------------ CURSES MAIN ------------------

def curses_main(stdscr, domain, amass_brute, sublister_ports, amass_ports, nmap_flag, port_label, dirb_wordlist):
    """The curses-based entry."""
    curses.start_color()
    # color pairs
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

    add_progress_line(stdscr, "[+] Press any key to exit the Recon Wizard...", color_pair=1)
    stdscr.getch()

# ------------------ MAIN ------------------

def main():
    if os.geteuid() != 0:
        print("[-] Please run as sudo to allow auto-install of missing packages.")
        sys.exit(1)

    print(ASCII_BANNER)
    print("[*] Loading Recon Wizard (Now with Naabu, GoWitness, Concurrency, CPU/MEM Stats, Timeline)...\n")

    if not PSUTIL_AVAILABLE:
        print("[!] psutil is not installed. CPU and Memory usage won't be displayed.\n"
              "Install psutil via pip3 install psutil or apt-get install python3-psutil.\n")

    domain = input("[?] Target domain (e.g., example.com): ").strip()
    if not domain:
        print("[-] No domain provided. Exiting.")
        sys.exit(1)

    brute_in = input("[?] Enable AMASS brute force? (y/N): ").lower().strip()
    amass_brute = (brute_in == "y")

    print("\nPort scanning approach (for Nmap, sublist3r, amass):")
    print("  1) Common HTTP/HTTPS only (80,443)")
    print("  2) Extended Common Ports => top 1000")
    print("  3) All 65535 TCP ports")
    port_choice = input("[?] Enter 1, 2, or 3: ").strip()

    sublister_ports = ""
    amass_ports = ""
    nmap_flag = ""
    port_label = ""

    if port_choice == "3":
        sublister_ports = "1-65535"
        amass_ports = "1-65535"
        nmap_flag = "-p-"
        port_label = "All 65535 TCP Ports"
    elif port_choice == "2":
        port_label = "Top 1000 Ports"
    else:
        sublister_ports = "80,443"
        amass_ports = "80,443"
        nmap_flag = "-p80,443"
        port_label = "Common HTTP/HTTPS (80,443)"

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

    print("\n[+] Script finished. All logs and data are in wizard_enum_<domain>/ subfolders.")
    print("[+] CPU/MEM usage was displayed in real-time if psutil was available.")
    print("[+] The ASCII timeline is shown at the end. Enjoy your hacker-esque recon!\n")

if __name__ == "__main__":
    main()
