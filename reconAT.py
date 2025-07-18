#!/usr/bin/env python3

import argparse
import os
import subprocess
import sys
import base64
import requests # Make sure to install this library: pip install requests
try:
    import shodan # Make sure to install this library: pip install shodan
except ImportError:
    print("[!] Error: The 'shodan' library is not installed. Please run 'pip install shodan'.")
    sys.exit(1)


# --- Configuration ---
# It's recommended to set API keys as environment variables for better security.
# Example: export CHAOS_KEY='your_key_here' | You can get one for free from https://cloud.projectdiscovery.io/scans?ref=api_key
# Example: export SHODAN_API_KEY='your_key_here'
# Please add the correct path to the regulator and change the Slack Webhook URL
CHAOS_KEY = os.environ.get("CHAOS_KEY")
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY") 
RECON_BASE_DIR = os.path.expanduser("~/ReconAT")
RECON_RESULTS_DIR = os.path.join(RECON_BASE_DIR, "recon-results")
REGULATOR_DIR = os.path.expanduser("~/regulator")
WORDLIST_PATH = os.path.expanduser("~/wordlists/directory-list-2.3-medium.txt")
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/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"

def run_command(command, cwd=None, shell=False):
    """
    A helper function to run external commands, print their output in real-time,
    and handle errors.
    """
    # If the command is passed as a string with shell=True, use it as is.
    # Otherwise, join the list for printing.
    cmd_str = command if isinstance(command, str) else ' '.join(command)
    print(f"\n[+] Running command: {cmd_str}")
    try:
        process = subprocess.Popen(
            command,
            stdout=sys.stdout,
            stderr=sys.stderr,
            cwd=cwd,
            shell=shell
        )
        process.communicate()
        if process.returncode != 0:
            print(f"[!] Command failed with exit code {process.returncode}: {cmd_str}")
    except FileNotFoundError:
        cmd_name = command.split()[0] if isinstance(command, str) else command[0]
        print(f"[!] Error: Command not found - `{cmd_name}`. Is it installed and in your PATH?")
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")

def create_directory(path):
    """Creates a directory if it doesn't exist."""
    if not os.path.exists(path):
        print(f"[*] Creating directory: {path}")
        os.makedirs(path)

def combine_and_unique_files(sources, destination):
    """Combines multiple text files, sorts them, and removes duplicates."""
    print(f"[*] Combining and sorting unique entries into {destination}")
    all_lines = set()
    for source_file in sources:
        if os.path.exists(source_file):
            with open(source_file, 'r') as f:
                all_lines.update(line.strip() for line in f)
        else:
            print(f"[!] Warning: Source file not found - {source_file}")

    with open(destination, 'w') as f:
        for line in sorted(list(all_lines)):
            # Remove wildcard prefix like '*.', which can come from some tools
            if line.startswith('*.'):
                line = line[2:]
            f.write(line + '\n')

def run_shodan_scan(target, target_dir):
    """
    Performs multiple Shodan searches for a given target and saves the unique IPs.
    Returns the path to the IP file on success, otherwise returns None.
    """
    print(f"[*] Starting Shodan scan for {target}...")
    if not SHODAN_API_KEY:
        print("[!] SHODAN_API_KEY not provided. Skipping Shodan scan.")
        return None

    api = shodan.Shodan(SHODAN_API_KEY)
    all_ips = set()
    queries = [
        f'hostname:"{target}"',
        f'ssl:"{target}"',
        f'ssl.cert.subject.CN:"{target}"'
    ]

    for query in queries:
        try:
            print(f"[*] Running Shodan query: {query}")
            results = api.search(query)
            found_ips = {result['ip_str'] for result in results['matches']}
            print(f"[*] Found {len(found_ips)} IPs for this query.")
            all_ips.update(found_ips)
        except shodan.APIError as e:
            print(f"[!] Shodan API error for query '{query}': {e}")
        except Exception as e:
            print(f"[!] An unexpected error occurred during Shodan scan: {e}")

    if all_ips:
        output_file = os.path.join(target_dir, "ips.txt")
        print(f"[*] Found a total of {len(all_ips)} unique IPs. Saving to {output_file}")
        with open(output_file, 'w') as f:
            for ip in sorted(list(all_ips)):
                f.write(ip + '\n')
        return output_file
    else:
        print("[*] No IPs found for the target in Shodan.")
        return None


def generate_dork_links(target, target_dir):
    """Generates an HTML file with various dorking links."""
    print("[*] Generating dorking links...")
    base_target = target.split('.')[0]
    output_file = os.path.join(target_dir, "dork_links.html")

    # Base64 encode for FOFA
    fofa_query = f'"{target}"'.encode('ascii')
    fofa_b64 = base64.b64encode(fofa_query).decode('ascii')

    dorks = {
        "Google Dork 1: site:*<{base_target}>*": f"https://www.google.com/search?q=site:*%3C{base_target}%3E*",
        "Google Dork 2: site:{base_target}>*": f"https://www.google.com/search?q=site:{base_target}%3E*",
        "Google Dork 3: site:*<{base_target}.*>*": f"https://www.google.com/search?q=site:*%3C{base_target}.*%3E*",
        "Google Dork 4: site:*<*{base_target}.*>*": f"https://www.google.com/search?q=site:*%3C*{base_target}.*%3E*",
        "Google Dork 5: site:*{base_target}.*": f"https://www.google.com/search?q=site:*{base_target}.*",
        f"Whoxy: {base_target}": f"https://www.whoxy.com/search.php?company={base_target}",
        f"FOFA: {target} (Base64)": f"https://en.fofa.info/result?qbase64={fofa_b64}",
    }

    html_content = f"""
    <html>
    <head><title>Dork Links for {base_target}</title></head>
    <body>
        <h1>Dork Links for {base_target}</h1>
        <ul>
    """
    for text, link in dorks.items():
        html_content += f"<li><a href='{link}' target='_blank'>{text}</a></li>\n"

    html_content += """
        </ul>
    </body>
    </html>
    """
    with open(output_file, 'w') as f:
        f.write(html_content)
    print(f"[*] Dork links saved to {output_file}")

def send_slack_notification(message):
    """Sends a notification to a Slack webhook."""
    print("[*] Sending Slack notification...")
    try:
        response = requests.post(
            SLACK_WEBHOOK_URL,
            json={"text": message},
            headers={'Content-Type': 'application/json'}
        )
        if response.status_code == 200:
            print("[+] Slack notification sent successfully.")
        else:
            print(f"[!] Failed to send Slack notification. Status: {response.status_code}, Response: {response.text}")
    except Exception as e:
        print(f"[!] Error sending Slack notification: {e}")


def main(target):
    """Main function to run the reconnaissance process."""
    print(f"--- Starting Reconnaissance for: {target} ---")
    
    # --- Setup ---
    target_dir = os.path.join(RECON_RESULTS_DIR, target)
    create_directory(target_dir)
    sitename = target.split('.')[0]

    # Define file paths
    subfinder_out = os.path.join(target_dir, f"{target}-subfinder.txt")
    chaos_out = os.path.join(target_dir, f"{target}-chaos.txt")
    all_subdomains_file = os.path.join(target_dir, f"{target}-subdomains.txt")
    alive_subdomains_file = os.path.join(target_dir, "alive_subdomains.txt")
    
    # --- Subdomain Enumeration ---
    run_command(["subfinder", "-d", target, "-o", subfinder_out])
    if CHAOS_KEY:
        run_command(["chaos", "-d", target, "-o", chaos_out, "-key", CHAOS_KEY])
    else:
        print("[!] CHAOS_KEY not set. Skipping Chaos scan.")

    combine_and_unique_files([subfinder_out, chaos_out], all_subdomains_file)

    # --- Regulator for More Subdomains (Optional, requires specific setup) ---
    # This section is complex and depends on a tool called 'regulator'.
    # Ensure it is set up correctly at REGULATOR_DIR.
    print("[*] Running Regulator to find more subdomains...")
    regulator_target_file = os.path.join(REGULATOR_DIR, sitename)
    run_command(f"cp {all_subdomains_file} {regulator_target_file}", shell=True)
    run_command(["python3", "main.py", "-t", target, "-f", sitename, "-o", f"{sitename}.brute"], cwd=REGULATOR_DIR)
    run_command(["puredns", "resolve", f"{sitename}.brute", "--write", f"{sitename}.valid"], cwd=REGULATOR_DIR)
    # Using python to get the difference instead of `comm`
    with open(os.path.join(REGULATOR_DIR, f"{sitename}.valid"), 'r') as f_valid, \
         open(regulator_target_file, 'r') as f_orig:
        valid_subs = set(f_valid.read().splitlines())
        orig_subs = set(f_orig.read().splitlines())
        final_subs = sorted(list(valid_subs - orig_subs))
    
    regulator_final_file = os.path.join(target_dir, f"{sitename}-regulator.txt")
    with open(regulator_final_file, 'w') as f:
        f.write('\n'.join(final_subs))
    
    # Append regulator results back to the main subdomain list
    with open(all_subdomains_file, 'a') as f_all, open(regulator_final_file, 'r') as f_reg:
        f_all.write(f_reg.read())
    
    # Clean up regulator files
    run_command(f"rm {REGULATOR_DIR}/{sitename}*", shell=True)


    # --- Finding Alive Subdomains ---
    print("[*] Finding alive subdomains with httpx...")
    run_command(f"cat {all_subdomains_file} | httpx -silent > {alive_subdomains_file}", shell=True)

    # --- Shodan IP Extraction and VHOST Scan ---
    ips_file = run_shodan_scan(target, target_dir) # This now returns the file path or None
    
    if ips_file:
        print("[*] Starting vhost scan on IPs found by Shodan...")
        vhosts_dir = os.path.join(target_dir, "vhosts-scan")
        create_directory(vhosts_dir)
        with open(ips_file, 'r') as f:
            for ip in f:
                ip = ip.strip()
                if ip:
                    ffuf_cmd = [
                        "ffuf", "-w", all_subdomains_file, "-u", f"https://{ip}",
                        "-H", "Host: FUZZ", "-of", "html", "-o", os.path.join(vhosts_dir, f"{ip}.html")
                    ]
                    run_command(ffuf_cmd)
    else:
        print("[*] Skipping vhost scan as no IPs were found or Shodan API key was not provided.")


    # --- FFUF Directory Brute-Force ---
    print("[*] Starting directory brute-force with FFUF on alive subdomains...")
    ffuf_results_dir = os.path.join(target_dir, "ffuf-results")
    create_directory(ffuf_results_dir)
    if os.path.exists(alive_subdomains_file):
        with open(alive_subdomains_file, 'r') as f:
            for subdomain in f:
                subdomain = subdomain.strip()
                if subdomain:
                    # Sanitize subdomain to create a valid filename
                    filename_sub = subdomain.replace("https://", "").replace("http://", "").replace(":", "_")
                    output_file = os.path.join(ffuf_results_dir, f"{filename_sub}-ffuf.html")
                    ffuf_cmd = [
                        "ffuf", "-c", "-w", WORDLIST_PATH, "-u", f"{subdomain}/FUZZ",
                        "-H", "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0",
                        "-ac", "-mc", "200,401,403,302", "-v", "-rate", "100",
                        "-of", "html", "-o", output_file
                    ]
                    run_command(ffuf_cmd)
    print("[+] Directory Brute-Force Completed.")

    # --- Port Scanning with Naabu ---
    print("[*] Starting port scan with Naabu...")
    naabu_out = os.path.join(target_dir, f"{sitename}-portscan.txt")
    run_command([
        "naabu", "-top-ports", "1000", "-list", all_subdomains_file,
        "-exclude-ports", "80,443,8443,21,25,22", "-o", naabu_out
    ])
    print("[+] Port Scan Completed.")

    # --- XSS Parameter Mining ---
    print("[*] Searching for potential XSS parameters...")
    wayback_urls = os.path.join(target_dir, "waybackurls.txt")
    param_urls = os.path.join(target_dir, "parameterized-urls.txt")
    kxss_out = os.path.join(target_dir, "illegal-characters-check.txt")

    run_command(f"cat {alive_subdomains_file} | gau --providers wayback | gf xss > {wayback_urls}", shell=True)
    run_command(f"uddup -u {wayback_urls} -o {param_urls}", shell=True)
    run_command(f"cat {param_urls} | kxss > {kxss_out}", shell=True)
    if os.path.exists(wayback_urls):
        os.remove(wayback_urls) # Clean up intermediate file
    print("[+] XSS parameter search completed.")

    # --- Final Dorking and Cleanup ---
    generate_dork_links(target, target_dir)

    # --- Final Notification ---
    print("\n--- Recon Scan Done! ---")
    send_slack_notification(f"The Recon Scan for {target} is completed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="A comprehensive reconnaissance script to find and analyze subdomains."
    )
    parser.add_argument(
        "target",
        help="The target domain to scan (e.g., example.com)"
    )
    args = parser.parse_args()

    # --- Pre-run Checks for command-line tools ---
    required_tools = ["subfinder", "chaos", "httpx", "ffuf", "naabu", "gau", "gf", "uddup", "kxss", "puredns", "dig"]
    for tool in required_tools:
        if subprocess.run(['which', tool], capture_output=True, text=True).returncode != 0:
            print(f"[!] Critical Error: Required tool '{tool}' is not installed or not in PATH. Please install it to continue.")
            sys.exit(1)

    main(args.target)
