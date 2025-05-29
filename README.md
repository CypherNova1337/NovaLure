# NovaLure - OAST Scanner
**NovaLure - OAST Scanner by Cyphernova1337**
**Version 1.1**

## Overview
NovaLure is a Python-based automation tool designed to assist in Out-of-Band Application Security Testing (OAST). It automates the process of sending common OAST payloads to a list of target URLs and helps in identifying potential vulnerabilities like Blind Server-Side Request Forgery (SSRF).

For bug bounty hunters and penetration testers, NovaLure can serve as a valuable tool for:

* Automating specific OAST checks that might otherwise be done manually (e.g., in Burp Suite Repeater with Collaborator payloads).
* Performing scalable initial reconnaissance across many targets for common header-based and request-target SSRF vulnerabilities.
* Providing a free, customizable alternative for certain automated OAST detections, complementing tools like Burp Suite.

The tool automatically starts an `interactsh-client` instance, captures its unique OAST domain, crafts unique payloads for different test methods, sends them to targets, and then correlates any detected out-of-band interactions back to the specific payloads and targets.

---
## Features
* **Automatic Interactsh Integration**:
    * Starts `interactsh-client` in the background.
    * Automatically captures the unique Interactsh base domain.
    * Logs all Interactsh client interactions to a temporary JSON file.
* **Target Discovery (Optional)**:
    * Uses `assetfinder` to discover subdomains from a root domain list.
    * Uses `httprobe` to identify live HTTP/S services from the discovered subdomains.
    * Flags to skip these steps if you already have a list of live URLs.
* **Multiple OAST Payload Types**:
    * Tests for common OAST vectors using:
        * `X-Forwarded-For` header
        * `X-Forwarded-Host` header
        * `Host` header
        * HTTP Request-Target modification (via `curl`)
* **Unique Payload Identifiers**: Generates unique OAST subdomains for each test on each target, allowing for precise correlation of interactions.
* **Client-Side Clue Detection**:
    * Checks for direct reflection of OAST payloads in HTTP response bodies.
    * Identifies potential Open Redirects if the server redirects to the OAST domain.
* **Interaction Correlation**: Parses the `interactsh-client`'s log of hits and matches them back to the specific payloads sent by NovaLure.
* **Reporting**:
    * Generates a detailed Markdown report (`NovaLure_Report.md` by default) summarizing:
        * Scan metadata and summary.
        * Detailed findings per target, including which payloads received OAST interactions, direct reflections, or open redirects.
        * Details of OAST interactions (protocol, source IP, timestamp, raw HTTP request snippet).
* **Console Output Control**:
    * Colored console output for better readability.
    * Standard, verbose (`-v`), and quiet (`-q`) modes.
* **Configurable**: Command-line arguments for input file, output report, request timeout, Interactsh server, and skipping reconnaissance steps.

---
## Prerequisites
* **Python 3**: The script is written for Python 3.
* **`requests` Library**:
    ```bash
    pip install requests
    ```
* **External Tools** (must be in your system's `PATH`):
    * **`interactsh-client`**: From ProjectDiscovery. Installation:
        ```bash
        go install -v [github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest](https://github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest)
        ```
    * **`assetfinder`**: From Tomnomnom. Installation:
        ```bash
        go install -v [github.com/tomnomnom/assetfinder@latest](https://github.com/tomnomnom/assetfinder@latest)
        ```
    * **`httprobe`**: From Tomnomnom. Installation:
        ```bash
        go install -v [github.com/tomnomnom/httprobe@latest](https://github.com/tomnomnom/httprobe@latest)
        ```
    * **`curl`**: Usually pre-installed on most Linux/macOS systems.

---
## Setup
1.  Save the script as `NovaLure.py` (or your preferred name).
2.  Make it executable:
    ```bash
    chmod +x NovaLure.py
    ```
3.  Ensure all prerequisite tools (`interactsh-client`, `assetfinder`, `httprobe`, `curl`) are installed and accessible via your system's `PATH`.
4.  Prepare an input file (e.g., `domains.txt`) containing root domains or full URLs (one per line).

---
## Usage
```bash
python3 NovaLure.py [OPTIONS]
```
or if executable:
```
./NovaLure.py [OPTIONS]
```
```
Command-Line Arguments:

usage: NovaLure.py [-h] [-i INPUT_FILE] [-o OUTPUT_FILE] [-t TIMEOUT]
                   [--interactsh-server INTERACTSH_SERVER]
                   [--skip-assetfinder] [--skip-httprobe]
                   [--keep-interactsh-log] [-v] [-q]

NovaLure: OAST (Out-of-Band Application Security Testing) automation tool.

options:
  -h, --help            show this help message and exit
  -i INPUT_FILE, --input-file INPUT_FILE
                        File containing target domains or URLs (one per line).
                        Default: domains.txt
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        Markdown file to save the scan report.
                        Default: NovaLure_Report.md
  -t TIMEOUT, --timeout TIMEOUT
                        Timeout in seconds for HTTP requests.
                        Default: 10
  --interactsh-server INTERACTSH_SERVER
                        Interactsh server URL for the client to connect to.
                        Default: [https://interact.sh](https://interact.sh)
  --skip-assetfinder    Skip assetfinder (if input file contains subdomains or
                        full URLs).
  --skip-httprobe       Skip httprobe (if input file contains live HTTP/S
                        URLs).
  --keep-interactsh-log
                        Keep the temporary Interactsh JSON log
                        (interactsh_temp_hits.json) after the scan.
  -v, --verbose         Enable verbose output, including DEBUG messages.
  -q, --quiet           Suppress most informational console output; only show
                        critical errors or major findings.
```

Examples:

Run with default settings (input domains.txt, output NovaLure_Report.md):

```
python3 NovaLure.py
```
Specify input and output files, and use an alternative Interactsh server (if interact.sh is unresolvable):
```
python3 NovaLure.py -i my_targets.txt -o scan_results.md --interactsh-server https://oast.pro
```
Run in verbose mode with a longer timeout:
```
python3 NovaLure.py -v -t 20
```
Skip recon tools if my_live_urls.txt contains full, live URLs:
```
python3 NovaLure.py -i my_live_urls.txt --skip-assetfinder --skip-httprobe
```
Output

    Console: Provides live feedback.
        Default mode: Clean, colored status updates.
        Verbose mode (-v): Detailed logs, including DEBUG messages for troubleshooting.
        Quiet mode (-q): Minimal output.
    Markdown Report: (e.g., NovaLure_Report.md)
        A comprehensive summary of the scan.
        Lists each target and the results of each OAST test method.
        Highlights direct payload reflections, potential open redirects.
        Crucially, details any confirmed out-of-band interactions (DNS, HTTP) received by Interactsh, correlated back to the specific payload and target. Includes source IP of interaction, timestamp, and raw HTTP request snippets.
    interactsh_temp_hits.json (Temporary):
        Raw JSON log from the interactsh-client. Deleted by default unless --keep-interactsh-log is used.

How It Works (and Relation to Tools like Burp Suite)

NovaLure complements a security tester's toolkit by automating specific OAST checks:

    Initialization: Starts interactsh-client (an alternative to relying solely on Burp Collaborator) and captures a unique base OAST domain.
    Target Enumeration (Optional): Similar to how one might use various tools to build a target list for Burp Suite.
    OAST Payload Delivery: For each live target URL:
        Generates unique OAST interaction URLs.
        Sends HTTP requests with these OAST URLs embedded in common vectors. This automates what might be done manually in Burp Repeater for these specific checks.
    Response Analysis (Client-Side): Checks immediate HTTP responses.
    Interaction Monitoring & Correlation: interactsh-client logs interactions. NovaLure then correlates these back to the sent payloads. This is akin to checking the Burp Collaborator client, but automated and logged.
    Reporting: Generates a Markdown report for review and potential further investigation using tools like Burp Suite.

Important Notes

    DNS Resolution: The default Interactsh server is https://interact.sh. If your machine has trouble resolving this (check with ping interact.sh), use the --interactsh-server flag with an alternative like https://oast.pro.
    Tool Paths: Ensure interactsh-client, assetfinder, and httprobe are in your system's PATH.
    Permissions: The script needs execute permissions (chmod +x NovaLure.py).

Future Enhancements

    Concurrency (e.g., asyncio with httpx) for faster scanning.
    Option for Python-native recon to reduce external tool dependencies.
    More payload types and encoding options.

License

This project is open-source. Consider using a license like MIT if you plan to share it widely.
