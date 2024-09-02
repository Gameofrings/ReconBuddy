

## ReconBuddy

**ReconBuddy** is a comprehensive reconnaissance automation script designed for bug bounty hunters and security researchers. This tool automates the process of gathering information about target domains, including subdomain enumeration, vulnerability scanning, and much more.

### Features

- **Subdomain Enumeration**: Automatically discover subdomains using tools like `crt.sh`, `assetfinder`, `subfinder`, `amass`, and more.
- **CORS Misconfiguration Detection**: Identify potential Cross-Origin Resource Sharing (CORS) vulnerabilities.
- **CMS Detection**: Detect Content Management Systems (CMS) in use by the target.
- **HTTP Request Smuggling**: Scan for HTTP request smuggling vulnerabilities.
- **Open Redirect Scanning**: Identify possible open redirect vulnerabilities.
- **Endpoint Discovery**: Extract endpoints from various sources like gau, waybackurls, and others.
- **SQL Injection Testing**: Automate SQL injection testing using `SQLMap` and `Ghauri`.
- **XSS Detection: Automate the detection of Cross-Site Scripting (XSS) vulnerabilities.
- **SSTI Detection: Scan for Server-Side Template Injection (SSTI) vulnerabilities.
### Prerequisites

Before running the script, ensure the following tools are installed and accessible in your system’s PATH:

- `curl`
- `jq`
- `chaos`
- `assetfinder`
- `subfinder`
- `python3`
- `amass`
- `gobuster`
- `knockpy`
- `altdns`
- `httpx`
- `nuclei`
- `whatweb`
- `gau`
- `waybackurls`
- `katana`
- `hakrawler`

### Python Dependencies

Install the required Python packages by running:

```bash
pip install -r requirements.txt
```

### Installation

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/Gameofrings/ReconBuddy.git
   cd ReconBuddy
   ```

2. **Set Up Environment Variables**:

   - Ensure you have a `GITHUB_TOKEN` environment variable set for GitHub API access.

3. **Configure Paths**:

   - Update the `WORDLIST_PATH` variable in the script to point to your wordlist file.

### Usage

1. **Run the Script**:

   ```bash
   python3 ReconBuddy.py
   ```

2. **Provide the Target Domain**:

   - When prompted, enter the target domain. The script will then execute a series of reconnaissance tasks and save the results in the current directory.

### Output

The script generates various output files, each corresponding to the tool used. These files are saved in the current directory with appropriate names, making it easy to review the findings.

### Contributing

Contributions are welcome! If you’d like to improve ReconBuddy or add new features, feel free to fork the repository, make your changes, and submit a pull request.

### License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

---


