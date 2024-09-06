import subprocess
import os
import platform
import shutil


# List of Go tools and their respective install commands
def get_latest_go_version():
    # Fetch the latest Go version from the official website
    try:
        result = subprocess.run(["curl", "-L", "-s", "https://golang.org/VERSION?m=text"], capture_output=True, text=True, check=True)
        version = result.stdout.strip().splitlines()[0]  # Ensure only the version is returned (first line)
        if not version.startswith('go'):
            version = "go1.20.7"  # Fallback version if fetching fails
        return version
    except subprocess.CalledProcessError:
        return "go1.20.7"  # Fallback version

def install_go(version, is_arm, rpi_3, rpi_4, is_mac):
    print(f"Installing/Updating Golang version {version}...")

    go_installed = shutil.which("go")
    try:
        if go_installed:
            current_version = subprocess.run(["go", "version"], capture_output=True, text=True).stdout.split()[2]
            if current_version == version:
                print(f"Golang is already installed and updated to {version}.")
                return
    except Exception:
        pass

    # Remove the existing Go installation
    subprocess.run(["sudo", "rm", "-rf", "/usr/local/go"], check=True)

    # Download the appropriate Go package based on the architecture and platform
    if is_arm:
        if rpi_3:
            download_url = f"https://dl.google.com/go/{version}.linux-armv6l.tar.gz"
        elif rpi_4:
            download_url = f"https://dl.google.com/go/{version}.linux-arm64.tar.gz"
    elif is_mac:
        if is_arm:
            download_url = f"https://dl.google.com/go/{version}.darwin-arm64.tar.gz"
        else:
            download_url = f"https://dl.google.com/go/{version}.darwin-amd64.tar.gz"
    else:
        download_url = f"https://dl.google.com/go/{version}.linux-amd64.tar.gz"

    # Download and extract Go
    download_path = f"/tmp/{version}.tar.gz"
    subprocess.run(["wget", download_url, "-O", download_path], check=True)
    subprocess.run(["sudo", "tar", "-C", "/usr/local", "-xzf", download_path], check=True)

    # Create symbolic link for Go binary
    subprocess.run(["sudo", "ln", "-sf", "/usr/local/go/bin/go", "/usr/local/bin/"], check=True)

    # Set environment variables for Golang
    go_env = """
# Golang vars
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$GOROOT/bin:$HOME/.local/bin:$PATH
"""
    profile_shell = os.getenv("SHELL")
    if profile_shell:
        profile_path = os.path.expanduser(f"~/.{os.path.basename(profile_shell)}rc")
        with open(profile_path, "a") as profile_file:
            profile_file.write(go_env)

    os.environ["GOROOT"] = "/usr/local/go"
    os.environ["GOPATH"] = os.path.expanduser("~/go")
    os.environ["PATH"] = f"{os.environ['GOPATH']}/bin:{os.environ['GOROOT']}/bin:{os.environ.get('PATH')}"

    print("Golang installed successfully.")

def check_go_env():
    if "GOPATH" not in os.environ:
        print("GOPATH environment variable not detected. Add Golang env vars to your ~/.bashrc or ~/.zshrc:")
        print("export GOROOT=/usr/local/go")
        print("export GOPATH=$HOME/go")
        print("export PATH=$GOPATH/bin:$GOROOT/bin:$PATH")
        exit(1)

    if "GOROOT" not in os.environ:
        print("GOROOT environment variable not detected. Add Golang env vars to your ~/.bashrc or ~/.zshrc:")
        print("export GOROOT=/usr/local/go")
        print("export GOPATH=$HOME/go")
        print("export PATH=$GOPATH/bin:$GOROOT/bin:$PATH")
        exit(1)




go_tools = {
    "gf": "github.com/tomnomnom/gf@latest",
    "brutespray": "github.com/x90skysn3k/brutespray@latest",
    "qsreplace": "github.com/tomnomnom/qsreplace@latest",
    "amass": "github.com/owasp-amass/amass/v3/...@master",
    "ffuf": "github.com/ffuf/ffuf/v2@latest",
    "github-subdomains": "github.com/gwen001/github-subdomains@latest",
    "gitlab-subdomains": "github.com/gwen001/gitlab-subdomains@latest",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "anew": "github.com/tomnomnom/anew@latest",
    "notify": "github.com/projectdiscovery/notify/cmd/notify@latest",
    "unfurl": "github.com/tomnomnom/unfurl@v0.3.0",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "github-endpoints": "github.com/gwen001/github-endpoints@latest",
    "dnsx": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "subjs": "github.com/lc/subjs@latest",
    "Gxss": "github.com/KathanP19/Gxss@latest",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
    "crlfuzz": "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest",
    "dalfox": "github.com/hahwul/dalfox/v2@latest",
    "puredns": "github.com/d3mondev/puredns/v2@latest",
    "interactsh-client": "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
    "analyticsrelationships": "github.com/Josue87/analyticsrelationships@latest",
    "gotator": "github.com/Josue87/gotator@latest",
    "roboxtractor": "github.com/Josue87/roboxtractor@latest",
    "mapcidr": "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest",
    "cdncheck": "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest",
    "dnstake": "github.com/pwnesia/dnstake/cmd/dnstake@latest",
    "tlsx": "github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
    "gitdorks_go": "github.com/damit5/gitdorks_go@latest",
    "smap": "github.com/s0md3v/smap/cmd/smap@latest",
    "dsieve": "github.com/trickest/dsieve@master",
    "inscope": "github.com/tomnomnom/hacks/inscope@latest",
    "enumerepo": "github.com/trickest/enumerepo@latest",
    "Web-Cache-Vulnerability-Scanner": "github.com/Hackmanit/Web-Cache-Vulnerability-Scanner@latest",
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "hakip2host": "github.com/hakluke/hakip2host@latest",
    "gau": "github.com/lc/gau/v2/cmd/gau@latest",
    "mantra": "github.com/MrEmpy/mantra@latest",
    "crt": "github.com/cemulus/crt@latest",
    "s3scanner": "github.com/sa7mon/s3scanner@latest",
    "nmapurls": "github.com/sdcampbell/nmapurls@latest",
    "shortscan": "github.com/bitquark/shortscan/cmd/shortscan@latest",
    "sns": "github.com/sw33tLie/sns@latest",
    "ppmap": "github.com/kleiton0x00/ppmap@latest",
    "sourcemapper": "github.com/denandz/sourcemapper@latest",
    "jsluice": "github.com/BishopFox/jsluice/cmd/jsluice@latest"
}

# List of repositories and their GitHub URLs
repos = {
    "dorks_hunter": "six2dez/dorks_hunter",
    "dnsvalidator": "vortexau/dnsvalidator",
    "interlace": "codingo/Interlace",
    "wafw00f": "EnableSecurity/wafw00f",
    "gf": "tomnomnom/gf",
    "Gf-Patterns": "1ndianl33t/Gf-Patterns",
    "Corsy": "s0md3v/Corsy",
    "CMSeeK": "Tuhinshubhra/CMSeeK",
    "fav-up": "pielco11/fav-up",
    "massdns": "blechschmidt/massdns",
    "Oralyzer": "r0075h3ll/Oralyzer",
    "testssl": "drwetter/testssl.sh",
    "commix": "commixproject/commix",
    "JSA": "w9w/JSA",
    "cloud_enum": "initstring/cloud_enum",
    "ultimate-nmap-parser": "shifty0g/ultimate-nmap-parser",
    "pydictor": "LandGrey/pydictor",
    "gitdorks_go": "damit5/gitdorks_go",
    "urless": "xnl-h4ck3r/urless",
    "smuggler": "defparam/smuggler",
    "Web-Cache-Vulnerability-Scanner": "Hackmanit/Web-Cache-Vulnerability-Scanner",
    "regulator": "cramppet/regulator",
    "ghauri": "r0oth3x49/ghauri",
    "gitleaks": "gitleaks/gitleaks",
    "trufflehog": "trufflesecurity/trufflehog",
    "nomore403": "devploit/nomore403",
    "SwaggerSpy": "UndeadSec/SwaggerSpy",
    "LeakSearch": "JoelGMSec/LeakSearch",
    "ffufPostprocessing": "Damian89/ffufPostprocessing",
    "misconfig-mapper": "intigriti/misconfig-mapper",
    "Spoofy": "MattKeeley/Spoofy"
}

# Function to install Go tools
def install_go_tools():
    print("Installing Go tools...")
    for tool, repo in go_tools.items():
        try:
            print(f"Installing {tool}...")
            subprocess.run(f"go install -v {repo}", shell=True, check=True)
        except subprocess.CalledProcessError:
            print(f"Failed to install {tool}, please try manually.")

# Function to clone repositories
def clone_repos(dir_path):
    print("Cloning repositories...")
    os.makedirs(dir_path, exist_ok=True)
    for repo_name, repo_url in repos.items():
        repo_path = os.path.join(dir_path, repo_name)
        if not os.path.exists(repo_path):
            try:
                print(f"Cloning {repo_name}...")
                subprocess.run(f"git clone https://github.com/{repo_url} {repo_path}", shell=True, check=True)
            except subprocess.CalledProcessError:
                print(f"Failed to clone {repo_name}, please try manually.")

# Function to install Python requirements
def install_requirements(requirements_file):
    if os.path.exists(requirements_file):
        print("Installing Python requirements...")
        subprocess.run(f"pip install -r {requirements_file}", shell=True, check=True)

# Function to install system packages
def install_system_packages():
    distro = platform.system().lower()
    print(f"Installing system packages for {distro}...")
    
    if distro == "linux":
        subprocess.run("sudo apt update && sudo apt install python3 python3-pip build-essential git -y", shell=True, check=True)
    elif distro == "darwin":
        subprocess.run("/bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"", shell=True, check=True)
        subprocess.run("brew install python git", shell=True, check=True)
    elif distro == "windows":
        print("Please manually install the required packages on Windows.")
    else:
        print(f"Unsupported OS: {distro}")

def main():
    tools_dir = os.path.expanduser("~/tools")
    
    # Step 1: Install system packages
    install_system_packages()
     # Detect system information
    arch = platform.machine()
    is_arm = arch in ["arm64", "armv6l", "aarch64"]
    rpi_3 = arch == "armv6l"
    rpi_4 = arch == "arm64"
    is_mac = platform.system().lower() == "darwin"

    # Fetch the latest Go version
    version = get_latest_go_version()

    # Install or update Golang
    install_go(version, is_arm, rpi_3, rpi_4, is_mac)

    # Check Go environment variables
    check_go_env()
    # Step 2: Install Go tools
    install_go_tools()

    # Step 3: Clone repositories
    clone_repos(tools_dir)

    # Step 4: Install Python requirements
    requirements_file = os.path.join(tools_dir, "requirements.txt")
    install_requirements(requirements_file)

    print("Installation completed!")

if __name__ == "__main__":
    main()
