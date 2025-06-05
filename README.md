<p align="center">
  </p>

<h1 align="center">NovaLure - OAST Automation Perfected</h1>

<p align="center">
  <strong>Unleash the power of Out-of-Band Application Security Testing (OAST) with NovaLure!</strong><br />
  Automated discovery of Blind SSRF, Open Redirects, and other out-of-band vulnerabilities.
  <br /><i>By Cyphernova1337</i>
  <br /><br />
  <img src="https://img.shields.io/badge/python-3.x-blue.svg" alt="Python 3.x">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT">
  </p>

---

NovaLure is your smart assistant for OAST, designed for bug bounty hunters and penetration testers. It streamlines the detection of vulnerabilities that require out-of-band interaction, integrating seamlessly with Interactsh. Automate common header-based attacks, request-target manipulation, and fuzz GET parameters for open redirects.

Whether you're looking to scale your initial reconnaissance or find an alternative to manual OAST checks, NovaLure helps you uncover critical vulnerabilities efficiently.

## ✨ Features

* 🚀 **Automatic Interactsh Integration:** Hands-free setup and OAST domain capture.
* 🎯 **Intelligent Target Discovery (Optional):** Leverages `assetfinder` and `httprobe` to find live targets.
* 🛡️ **Diverse OAST Attack Vectors:**
    * Header Injections: `X-Forwarded-For`, `X-Forwarded-Host`, `Host`.
    * HTTP Request-Target Manipulation (for Blind SSRF).
    * GET Parameter Fuzzing for Open Redirects with an extensive payload list.
* 🔗 **Precise Interaction Correlation:** Unique payload identifiers for pinpointing vulnerable sources.
* 👁️ **Client-Side Clue Detection:** Identifies direct reflections and potential/verified open redirects.
* 📊 **Comprehensive Markdown Reporting:** Detailed, actionable reports for your findings.
* 🎨 **User-Friendly Console:** Colored output with standard, verbose (`-v`), and quiet (`-q`) modes.
* 🔧 **Highly Configurable:** Fine-tune scans with command-line arguments.

---

## 🛠️ Prerequisites

1.  **Python 3**
2.  **`requests` Library:**
    ```
    pip install requests
    ```
3.  **Go-lang Based Tools** (ensure Go is installed and your `GOPATH/bin` or `GOBIN` is in your system's `PATH`):
    * **`interactsh-client`** (ProjectDiscovery):
        ```
        go install -v https://github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
        ```
    * **`assetfinder`** (Tomnomnom):
        ```
        go install -v https://github.com/tomnomnom/assetfinder@latest
        ```
    * **`httprobe`** (Tomnomnom):
        ```
        go install -v https://github.com/tomnomnom/httprobe@latest
        ```
4.  **`curl`**: Standard on most Linux/macOS systems.

---

## 🚀 Getting Started

1.  **Obtain `NovaLure.py`:**
    Clone the repository or download the `NovaLure.py` script.
    ```
    
      git clone https://github.com/CypherNova1337/NovaLure.git
    
      cd NovaLure
    ```
2.  **Make it Executable:**
    ```
    chmod +x NovaLure.py
    ```
3.  **Prepare Targets:**
    Create a file (e.g., `targets.txt`) with root domains or full URLs, one per line. Alternatively, you can provide a single target directly via the command line or be prompted for input.
4.  **Run it!**
    See [Usage](#⚙️-usage) below.

---

## ⚙️ Usage

```
python3 NovaLure.py -h

```
```
usage: NovaLure2.py [-h] [-i INPUT_FILE] [-u URL] [-o OUTPUT_FILE] [-t TIMEOUT] [--interactsh-server INTERACTSH_SERVER] [--skip-assetfinder] [--skip-httprobe]
                    [--test-open-redirects] [--no-test-open-redirects] [--strict-redirects] [--keep-interactsh-log] [-v] [-q]

NovaLure: OAST (Out-of-Band Application Security Testing) automation tool.

options:
  -h, --help            show this help message and exit
  -i, --input-file INPUT_FILE
                        File containing target domains or URLs (one per line).
  -u, --url URL         Single target URL or domain (e.g., example.com) to scan.
  -o, --output-file OUTPUT_FILE
                        Markdown file to save the scan report.
                        Default: NovaLure_Report.md
  -t, --timeout TIMEOUT
                        Timeout in seconds for HTTP requests.
                        Default: 10
  --interactsh-server INTERACTSH_SERVER
                        Interactsh server URL for the client to connect to.
                        Default: https://interact.sh
  --skip-assetfinder    Skip assetfinder.
  --skip-httprobe       Skip httprobe.
  --test-open-redirects
                        Enable detailed fuzzing for Open Redirects in GET parameters (Enabled by default).
  --no-test-open-redirects
                        Disable detailed fuzzing for Open Redirects in GET parameters.
  --strict-redirects    Only report header-based Open Redirects if verified by a client-side OAST hit.
  --keep-interactsh-log
                        Keep the temporary Interactsh JSON log (interactsh_temp_hits.json).
  -v, --verbose         Enable verbose output.
  -q, --quiet           Suppress most informational console output.
```

Examples:

   Interactive input (if no -i or -u):
   ```

python3 NovaLure.py --interactsh-server https://oast.pro
   
   ```
(Will prompt: "Enter a single domain... or path to a file...")

Scan a single domain:
```

python3 NovaLure.py -u example.com --interactsh-server https://oast.pro
```
Scan from a file with verbose output:
```

python3 NovaLure.py -i targets.txt -v --interactsh-server https://oast.pro
```
Scan live URLs, disabling open redirect parameter fuzzing:
```

    python3 NovaLure.py -i live_urls.txt --skip-assetfinder --skip-httprobe --no-test-open-redirects
```
📄 Output Interpretation

    Console: Live updates on the scan progress. Use -v for troubleshooting detailed steps.
    Markdown Report (NovaLure_Report.md): The primary output. Contains:
        Scan summary (targets, OAST server used, scanner IP, etc.).
        Detailed findings per target, broken down by test method (Header OAST, Request-Target OAST, Open Redirect Parameter Fuzzing).
        Clear indication of:
            Server-Side OAST Interactions: DNS/HTTP hits from target infrastructure to your Interactsh domain.
            Verified Open Redirects: Both from parameter fuzzing (confirmed by an OAST hit) and header injections (if the redirect to OAST was followed and hit, especially by the scanner itself).
            Potential Open Redirects: For header injections, if a redirect to an OAST domain was issued by the server but a client-side hit wasn't correlated (visible if --strict-redirects is off).
            Direct Reflections: Payloads found in response bodies.
        Includes source IPs, timestamps, and raw request snippets for HTTP OAST interactions.

⚠️ Important Notes

    DNS Resolution for Interactsh: If interactsh-client fails to start (especially with "no address found for host" errors for the default interact.sh), your machine cannot resolve the default Interactsh server. Use the --interactsh-server <URL> flag with an alternative public server like https://oast.pro or https://oast.live.
    Tool Paths: Ensure interactsh-client, assetfinder, httprobe, and curl are in your system's PATH. If not, you can modify the *_PATH variables at the top of the NovaLure.py script.
    Permissions: The script needs execute permissions (chmod +x NovaLure.py).

💡 Future Enhancements

    Full asyncio concurrency for significantly faster scans.
    Python-native modules for reconnaissance to reduce external tool dependencies.
    Expanded OAST vectors (e.g., JSON/XML body injections, Blind XSS to OAST).
    Deeper analysis and fingerprinting of interacting OAST sources.

📜 License

This project is open-source. Consider licensing under the MIT License.
