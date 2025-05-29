#!/usr/bin/env python3
import subprocess
import time
import re
import os
import json
import shlex
import argparse
from urllib.parse import urlparse, quote 
from datetime import datetime

# --- Global Configuration (Defaults) ---
DEFAULT_DOMAINS_FILE = "domains.txt"
DEFAULT_REPORT_FILE = "NovaLure_Report.md"
DEFAULT_REQUEST_TIMEOUT = 10
DEFAULT_INTERACTSH_SERVER_FOR_CLIENT = "https://interact.sh"

INTERACTSH_CLIENT_PATH = "interactsh-client"
ASSETFINDER_PATH = "assetfinder"
HTTPROBE_PATH = "httprobe"

# --- Global Variables ---
interactsh_base_domain = None
interactsh_process = None
INTERACTSH_TEMP_HITS_FILE = "interactsh_temp_hits.json"

# ANSI Colors
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

VERBOSE_MODE = False
QUIET_MODE = False

ANSI_ESCAPE_REGEX = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

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
    Version 1.2.1 (M4 Bugfix Attempt)
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
        
        if level == "DEBUG" and not VERBOSE_MODE: # Only print DEBUG if verbose explicitly on
             return
        print(f"{color}{prefix}{message}{Colors.ENDC if color else ''}")
    else: # Not verbose - minimal prefixes, more colors
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

def start_interactsh_client(server_url):
    """Starts interactsh-client, captures its base domain."""
    global interactsh_base_domain, interactsh_process, INTERACTSH_TEMP_HITS_FILE

    if os.path.exists(INTERACTSH_TEMP_HITS_FILE):
        os.remove(INTERACTSH_TEMP_HITS_FILE)

    console_log(f"Starting interactsh-client (Server: {server_url}, Output: {INTERACTSH_TEMP_HITS_FILE})...", level="INFO")
    command = (
        f"{INTERACTSH_CLIENT_PATH} -s {server_url} "
        f"-json -o {INTERACTSH_TEMP_HITS_FILE} -v -poll-interval 5"
    )
    
    interactsh_process = subprocess.Popen(
        shlex.split(command),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, 
        text=True,
        bufsize=1, 
        universal_newlines=True
    )

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
                console_log(f"Regex matched but capturing group 1 (domain) is empty. Match groups: {match.groups()}", level="WARN")
        else:
            if "[INF]" in line_for_regex and ".oast." in line_for_regex and not line_for_regex.startswith("[INF] Listing"): 
                 console_log(f"Line looked like OAST domain but specific regex didn't match cleaned line: '{line_for_regex}'", level="DEBUG")
                 console_log(f"    Original line (repr): {repr(original_line_stripped)}", level="DEBUG")

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

def get_live_urls_from_file(input_domains_file, skip_assetfinder=False, skip_httprobe=False):
    """Uses assetfinder and httprobe to get live URLs, or processes input directly."""
    console_log(f"Processing input from: {input_domains_file}", level="INFO")
    live_urls = []

    if not os.path.exists(input_domains_file):
        console_log(f"Input file not found: {input_domains_file}", level="ERROR")
        return []

    if skip_assetfinder and skip_httprobe:
        console_log("Skipping recon. Assuming input file contains live URLs.", level="INFO")
        with open(input_domains_file, "r") as f:
            live_urls = [line.strip() for line in f if line.strip().startswith(("http://", "https://"))]
        console_log(f"Loaded {len(live_urls)} URLs directly from input file.")
        return live_urls

    try:
        with open(input_domains_file, "r") as f:
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
            num_subs = len(subs_out.split())
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
            live_urls = [url.strip() for url in urls_out.splitlines() if url.strip()]
            console_log(f"httprobe found {len(live_urls)} live URLs.", level="SUCCESS" if live_urls else "WARN")
        else:
            console_log("Skipping httprobe.", level="INFO")
            raw_urls = [line.strip() for line in processed_subs.splitlines() if line.strip()]
            live_urls = []
            for url_item in raw_urls:
                if not url_item.startswith(("http://", "https://")):
                    live_urls.append(f"http://{url_item}") 
                else:
                    live_urls.append(url_item)
            if raw_urls and not any(u.startswith("http") for u in raw_urls): 
                 console_log("Protocols auto-prefixed to URLs as httprobe was skipped.",level="WARN")
    except FileNotFoundError as e:
        console_log(f"Tool not found: {e.filename}. Please ensure {e.filename} is installed and in your PATH.", level="FATAL")
        return []
    except Exception as e:
        console_log(f"Exception in get_live_urls_from_file: {e}", level="ERROR")
    return live_urls

def generate_oast_identifier(target_url_raw, method_tag_base, param_name=None):
    """Generates a unique identifier string for OAST payload, suitable for subdomains."""
    global interactsh_base_domain
    if not interactsh_base_domain:
        return None, None 
    
    parsed_target = urlparse(target_url_raw)
    target_host_sanitized = parsed_target.hostname.replace('.', '-') if parsed_target.hostname else "no-hostname"
    target_host_sanitized = re.sub(r'[^a-zA-Z0-9-]', '', target_host_sanitized)[:30].strip('-') 
    
    method_tag_sanitized = re.sub(r'[^a-zA-Z0-9-]', '', method_tag_base.lower())
    if param_name:
        param_name_sanitized = re.sub(r'[^a-zA-Z0-9-]', '', param_name.lower())[:10] 
        method_tag_sanitized = f"{method_tag_sanitized}-{param_name_sanitized}"

    timestamp_micro = str(int(time.time()*1000000)%1000000) 
    unique_part = f"{method_tag_sanitized}-{target_host_sanitized}-ts{timestamp_micro}"
    
    if len(unique_part) > 55: 
        unique_part = unique_part[:55] 
    unique_part = unique_part.strip('-') 
        
    full_oast_domain = f"{unique_part}.{interactsh_base_domain}"
    return full_oast_domain, unique_part

def test_url_for_oast(target_url, req_timeout):
    """Sends various OAST payloads to the target URL and returns findings."""
    console_log(f"Target: {target_url}", level="DEBUG")
    url_findings = {"target": target_url, "tests": []}
    
    import requests 

    test_methods = {
        "M1_XFF": {"header": "X-Forwarded-For"},
        "M2_XFH": {"header": "X-Forwarded-Host"},
        "M3_Host": {"header": "Host"},
        "M4_ReqTarget": {"special": True}
    }

    for tag, details in test_methods.items():
        oast_full_domain, oast_unique_id = generate_oast_identifier(target_url, tag) 
        if not oast_full_domain:
            console_log(f"Skipping {tag} for {target_url} due to OAST URL generation failure.", level="ERROR")
            url_findings["tests"].append({
                "method_tag": tag, "errors": ["OAST URL generation failed"], 
                "oast_identifier": oast_unique_id or "N/A", "oast_full_domain": oast_full_domain or "N/A", 
                "sent_payload_description":"N/A", "status_code": "Setup Error", "interactsh_hits":[]
            })
            continue

        current_test_info = {
            "method_tag": tag, "oast_identifier": oast_unique_id, "oast_full_domain": oast_full_domain, 
            "sent_payload_value": oast_full_domain, "sent_payload_description": "", "status_code": "Not Set", 
            "reflection_in_body": False, "open_redirect_found": None, "errors": [], "interactsh_hits": []
        }

        try:
            if "header" in details:
                header_name = details["header"]
                headers = {header_name: oast_full_domain, "User-Agent": "NovaLure-OAST-Scanner/1.2.1"}
                current_test_info["sent_payload_description"] = f"Header '{header_name}: {oast_full_domain}'"
                console_log(f"  [{tag}] Sending: {current_test_info['sent_payload_description']}", level="DEBUG")
                response = requests.get(target_url, headers=headers, timeout=req_timeout, allow_redirects=True, verify=False)
                current_test_info["status_code"] = response.status_code
                if oast_full_domain in response.text: current_test_info["reflection_in_body"] = True
                for r_hist in response.history:
                    if r_hist.status_code in [301, 302, 303, 307, 308] and r_hist.headers.get("Location") and oast_full_domain in r_hist.headers["Location"]:
                        current_test_info["open_redirect_found"] = r_hist.headers["Location"]; break
            
            elif tag == "M4_ReqTarget":
                target_for_m4_payload = f"http://{oast_full_domain}/M4_HIT_PATH_NOVALURE" 
                current_test_info["sent_payload_value"] = target_for_m4_payload
                current_test_info["sent_payload_description"] = f"Request-Target: {target_for_m4_payload}"
                console_log(f"  [{tag}] Sending: {current_test_info['sent_payload_description']}", level="DEBUG")
                
                status_code_from_curl = "M4_Status_Error" 
                process_result = None # Initialize to check if subprocess.run was attempted

                try:
                    # Using %% to escape % for f-string, ensuring literal %{http_code} for curl
                    curl_m4_cmd = (
                        f"curl -s -L --connect-timeout {int(req_timeout/2)} --max-time {req_timeout} "
                        f"-H \"User-Agent: NovaLure-OAST-Scanner/1.2.1\" " 
                        f"\"{target_url}\" --request-target \"{target_for_m4_payload}\" -o /dev/null -w \"%%{{http_code}}\""
                    )
                    process_result = subprocess.run(shlex.split(curl_m4_cmd), capture_output=True, text=True, timeout=req_timeout + 2)
                    
                    if process_result.stderr:
                        current_test_info["errors"].append(f"curl stderr: {process_result.stderr.strip()}")
                    
                    status_code_str = process_result.stdout.strip()
                    if status_code_str.isdigit() and len(status_code_str) == 3:
                        status_code_from_curl = int(status_code_str)
                    else:
                        status_code_from_curl = f"cURL_status: {status_code_str}" if status_code_str else "cURL_NoStatusOutput"
                
                except subprocess.TimeoutExpired:
                    current_test_info["errors"].append("curl command for M4 timed out.")
                    status_code_from_curl = "Timeout (curl M4)"
                except FileNotFoundError: 
                    current_test_info["errors"].append("curl command not found for M4.")
                    status_code_from_curl = "CurlNotFound (M4)"
                except Exception as sub_e: 
                    # This will catch other errors from subprocess.run or shlex.split
                    # including the potential NameError if it was somehow still occurring here.
                    current_test_info["errors"].append(f"Subprocess/Curl execution error for M4: {str(sub_e)}")
                    status_code_from_curl = "ErrorInCurlExec (M4)" # Consistent with report
                
                current_test_info["status_code"] = status_code_from_curl
        
        except requests.exceptions.Timeout: 
            current_test_info["errors"].append("Request timed out.")
            current_test_info["status_code"] = "Timeout"
        except requests.exceptions.RequestException as e: 
            current_test_info["errors"].append(str(e))
            current_test_info["status_code"] = "Request Error"
        except NameError as ne: 
            current_test_info["errors"].append(f"Unexpected NameError in test {tag}: {str(ne)}")
            current_test_info["status_code"] = "NameError in Test"
        except Exception as e: 
            current_test_info["errors"].append(f"Unexpected error in test method {tag}: {str(e)}")
            current_test_info["status_code"] = "Unexpected Script Error"
        
        # Join errors if list is not empty
        if current_test_info["errors"]:
            current_test_info["errors"] = "; ".join(current_test_info["errors"])
        else: # If list is empty, set to None for cleaner report
            current_test_info["errors"] = None

        url_findings["tests"].append(current_test_info)
        time.sleep(0.1) # Shorter delay
        
    return url_findings

def parse_and_correlate_interactsh_hits(all_tested_payloads_info):
    global INTERACTSH_TEMP_HITS_FILE
    console_log(f"Parsing Interactsh hits from {INTERACTSH_TEMP_HITS_FILE}...", level="INFO")
    
    if not os.path.exists(INTERACTSH_TEMP_HITS_FILE):
        console_log(f"Interactsh hits file not found: {INTERACTSH_TEMP_HITS_FILE}", level="WARN")
        return all_tested_payloads_info

    processed_hits_count = 0
    raw_hits_content = []
    try:
        with open(INTERACTSH_TEMP_HITS_FILE, "r") as f:
            raw_hits_content = f.readlines()
    except Exception as e:
        console_log(f"Error reading Interactsh hits file {INTERACTSH_TEMP_HITS_FILE}: {e}", level="ERROR")
        return all_tested_payloads_info

    for line in raw_hits_content:
        try:
            hit = json.loads(line.strip())
            hit_full_domain_interactsh = hit.get("full-id", hit.get("unique-id", "")) 
            
            if not hit_full_domain_interactsh:
                console_log(f"Skipping hit with missing 'full-id' or 'unique-id': {hit.get('protocol', 'N/A')}", level="DEBUG")
                continue
            
            matched_to_payload = False
            for url_payloads_info in all_tested_payloads_info:
                for test_info in url_payloads_info["tests"]:
                    if hit_full_domain_interactsh == test_info.get("oast_full_domain"):
                        hit_details = {
                            "protocol": hit.get("protocol"), "source_ip": hit.get("remote-address"),
                            "timestamp": hit.get("timestamp"),
                            "raw_request": hit.get("raw-request", None) if hit.get("protocol") == "http" else None,
                            "matched_oast_identifier": test_info.get("oast_identifier") 
                        }
                        test_info["interactsh_hits"].append(hit_details)
                        processed_hits_count += 1
                        matched_to_payload = True
            
            if not matched_to_payload:
                console_log(f"Unmatched Interactsh hit for domain (not tied to a sent payload): {hit_full_domain_interactsh}", level="DEBUG")
        except json.JSONDecodeError:
            pass 
    
    console_log(f"Correlated {processed_hits_count} Interactsh hits.", level="SUCCESS_IMPORTANT" if processed_hits_count > 0 else "INFO")
    return all_tested_payloads_info

def generate_markdown_report(all_tests_results, report_file_path, scan_start_time, scan_end_time, args):
    console_log(f"Generating Markdown report: {report_file_path}", level="INFO")
    
    with open(report_file_path, "w") as f:
        f.write(f"# NovaLure OAST Scan Report\n\n")
        f.write(f"**NovaLure - OAST Scanner by Cyphernova1337**\n\n") 
        f.write(f"- **Scan Started:** {scan_start_time.strftime('%Y-%m-%d %H:%M:%S %Z')}\n")
        f.write(f"- **Scan Finished:** {scan_end_time.strftime('%Y-%m-%d %H:%M:%S %Z')}\n")
        f.write(f"- **Input File:** `{args.input_file}`\n")
        f.write(f"- **Interactsh Server Used by Client:** `{args.interactsh_server}`\n")
        if interactsh_base_domain:
            f.write(f"- **Interactsh Base Domain Captured:** `{interactsh_base_domain}`\n")
        f.write("\n---\n\n")

        if not all_tests_results:
            f.write("## No URLs were tested or no results available.\n")
            return

        f.write("## Scan Summary\n\n")
        total_targets_tested = len(all_tests_results)
        targets_with_oast_hits = 0
        total_oast_interactions_recorded = 0
        
        for url_result in all_tests_results:
            url_had_oast_hit = False
            if url_result.get("tests"): 
                for test in url_result["tests"]:
                    if test.get("interactsh_hits"): 
                        url_had_oast_hit = True
                        total_oast_interactions_recorded += len(test["interactsh_hits"])
            if url_had_oast_hit:
                targets_with_oast_hits +=1
        
        f.write(f"- **Total Targets Processed:** {total_targets_tested}\n")
        f.write(f"- **Targets with OAST Interactions:** {targets_with_oast_hits}\n")
        f.write(f"- **Total OAST Interactions Recorded:** {total_oast_interactions_recorded}\n\n")
        f.write("---\n\n")
        
        f.write("## Detailed Findings\n\n")
        if not any(url_result.get("tests") for url_result in all_tests_results):
             f.write("No specific test results to display.\n")

        for url_result in all_tests_results:
            f.write(f"### Target: `{url_result.get('target', 'N/A')}`\n\n")
            if not url_result.get("tests"):
                f.write("  - No tests performed or recorded for this target.\n\n")
                continue

            has_any_finding_for_url = False
            for test in url_result["tests"]:
                if test.get("reflection_in_body") or test.get("open_redirect_found") or test.get("interactsh_hits") or test.get("errors"):
                    has_any_finding_for_url = True
                    f.write(f"  - **Test Method:** `{test.get('method_tag','N/A')}`\n")
                    f.write(f"    - **Sent Payload Description:** `{test.get('sent_payload_description','N/A')}`\n")
                    f.write(f"    - **OAST Full Domain Sent:** `{test.get('oast_full_domain','N/A')}`\n")
                    f.write(f"    - **OAST Identifier:** `{test.get('oast_identifier','N/A')}`\n")
                    if test.get('status_code') is not None: 
                        f.write(f"    - **Response Status (Direct):** `{test['status_code']}`\n")
                    if test.get("reflection_in_body"):
                        f.write(f"    - **Direct Reflection in Body:** `Yes`\n")
                    if test.get("open_redirect_found"):
                        f.write(f"    - **Potential Open Redirect To:** `{test['open_redirect_found']}`\n")
                    if test.get("errors"): # errors is now a string or None
                        f.write(f"    - **Errors During Test:** `{test['errors']}`\n")
                    
                    if test.get("interactsh_hits"):
                        f.write(f"    - **Interactsh Hits ✨:**\n")
                        for hit_num, hit in enumerate(test["interactsh_hits"], 1):
                            f.write(f"      - **Hit {hit_num}:**\n")
                            f.write(f"        - Protocol: `{hit.get('protocol')}`\n")
                            f.write(f"        - Source IP: `{hit.get('source_ip')}`\n")
                            f.write(f"        - Timestamp: `{hit.get('timestamp')}`\n")
                            f.write(f"        - Matched OAST Identifier: `{hit.get('matched_oast_identifier', 'N/A')}`\n")
                            if hit.get('raw_request') and hit.get('protocol') == 'http':
                                f.write(f"        - HTTP Request (first 300 chars):\n```http\n{hit['raw_request'][:300].strip()}...\n```\n")
                        f.write("\n") 
            if not has_any_finding_for_url:
                f.write("  - No direct reflections, open redirects, errors, or OAST hits recorded for this target under tested methods.\n")
            f.write("\n---\n\n")
    console_log(f"Markdown report generated: {report_file_path}", level="REPORT_INFO")

def main():
    global VERBOSE_MODE, QUIET_MODE
    parser = argparse.ArgumentParser(
        description="NovaLure: OAST (Out-of-Band Application Security Testing) automation tool.",
        formatter_class=argparse.RawTextHelpFormatter 
    )
    parser.add_argument(
        "-i", "--input-file",
        default=DEFAULT_DOMAINS_FILE,
        help=f"File containing target domains or URLs (one per line).\nDefault: {DEFAULT_DOMAINS_FILE}"
    )
    parser.add_argument(
        "-o", "--output-file",
        default=DEFAULT_REPORT_FILE,
        help=f"Markdown file to save the scan report.\nDefault: {DEFAULT_REPORT_FILE}"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=DEFAULT_REQUEST_TIMEOUT,
        help=f"Timeout in seconds for HTTP requests.\nDefault: {DEFAULT_REQUEST_TIMEOUT}"
    )
    parser.add_argument(
        "--interactsh-server",
        default=DEFAULT_INTERACTSH_SERVER_FOR_CLIENT,
        help=f"Interactsh server URL for the client to connect to.\nDefault: {DEFAULT_INTERACTSH_SERVER_FOR_CLIENT}"
    )
    parser.add_argument(
        "--skip-assetfinder",
        action="store_true",
        help="Skip assetfinder (if input file contains subdomains or full URLs)."
    )
    parser.add_argument(
        "--skip-httprobe",
        action="store_true",
        help="Skip httprobe (if input file contains live HTTP/S URLs)."
    )
    parser.add_argument(
        "--keep-interactsh-log",
        action="store_true",
        help=f"Keep the temporary Interactsh JSON log ({INTERACTSH_TEMP_HITS_FILE}) after the scan."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output, including DEBUG messages."
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress most informational console output; only show critical errors or major findings."
    )

    args = parser.parse_args()

    VERBOSE_MODE = args.verbose
    QUIET_MODE = args.quiet
    if VERBOSE_MODE and QUIET_MODE:
        print(f"{Colors.RED}{Colors.BOLD}[!] Cannot be both verbose (-v) and quiet (-q). Exiting.{Colors.ENDC}")
        return

    print_banner() 

    if os.path.exists(args.output_file):
        console_log(f"Output file {args.output_file} exists. It will be overwritten.", level="WARN")
        try:
            os.remove(args.output_file)
        except OSError as e:
            console_log(f"Could not remove existing report file {args.output_file}: {e}", level="ERROR")
            return 
    
    console_log("### NovaLure OAST Scanner Starting ###", level="INFO")
    scan_start_time = datetime.now()

    try:
        import requests
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    except ImportError:
        console_log("'requests' library not found. Please install it: pip install requests", level="FATAL")
        return

    if not start_interactsh_client(args.interactsh_server):
        console_log("Could not start or configure interactsh-client. Exiting.", level="FATAL")
        return
    
    if not interactsh_base_domain: 
        console_log("Interactsh base domain was not captured. Exiting.", level="FATAL")
        stop_interactsh_client() 
        return

    console_log(f"Interactsh client logging hits to temporary file: {INTERACTSH_TEMP_HITS_FILE}", level="INFO")
    console_log("Giving Interactsh client ~3 seconds to fully initialize before proceeding...", level="INFO")
    time.sleep(3)

    live_urls_to_test = get_live_urls_from_file(args.input_file, args.skip_assetfinder, args.skip_httprobe)
    all_scan_results = []

    if live_urls_to_test:
        console_log(f"Starting OAST tests on {len(live_urls_to_test)} URLs...", level="INFO")
        for i, url in enumerate(live_urls_to_test):
            if not QUIET_MODE and not VERBOSE_MODE:
                 print(f"{Colors.BLUE}[i] Testing URL {i+1}/{len(live_urls_to_test)}: {url}{Colors.ENDC}")
            elif VERBOSE_MODE : 
                 console_log(f"Testing URL {i+1}/{len(live_urls_to_test)}: {url}", level="INFO")

            url_results = test_url_for_oast(url, args.timeout)
            all_scan_results.append(url_results)
            time.sleep(0.5) 
    else:
        console_log("No live URLs found to test.", level="INFO")

    console_log("OAST payload delivery phase complete. Waiting 10 seconds for any lingering Interactsh interactions...", level="INFO")
    time.sleep(10) 

    stop_interactsh_client() 

    all_scan_results_with_hits = parse_and_correlate_interactsh_hits(all_scan_results)
    
    scan_end_time = datetime.now()
    generate_markdown_report(all_scan_results_with_hits, args.output_file, scan_start_time, scan_end_time, args)

    if not args.keep_interactsh_log and os.path.exists(INTERACTSH_TEMP_HITS_FILE):
        console_log(f"Removing temporary Interactsh log: {INTERACTSH_TEMP_HITS_FILE}", level="INFO")
        try:
            os.remove(INTERACTSH_TEMP_HITS_FILE)
        except OSError as e:
            console_log(f"Error removing temporary file {INTERACTSH_TEMP_HITS_FILE}: {e}", level="WARN")
    
    console_log("### NovaLure Scan Finished ###", level="SUCCESS_IMPORTANT")

if __name__ == "__main__":
    main()
