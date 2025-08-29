#!/bin/bash

# Bug Bounty Automation Script - Test Version
# Usage: ./script.sh <target_id>

set -e  # Exit on any error
trap 'echo "Script interrupted. Cleaning up..."; exit 1' INT TERM

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO")
            echo -e "${GREEN}[INFO]${NC} $timestamp - $message" | tee -a "$log_file"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $timestamp - $message" | tee -a "$log_file"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $timestamp - $message" | tee -a "$log_file"
            ;;
        "DEBUG")
            echo -e "${BLUE}[DEBUG]${NC} $timestamp - $message" | tee -a "$log_file"
            ;;
    esac
}

# Check if target ID is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <target_id>"
    exit 1
fi

# Define the datetime format
datetime=$(date '+%Y-%m-%d_%H-%M-%S')

# Setup paths and variables
id="$1"
path="$(pwd)"
scope_path="$path/scope/$id"
scan_path="$path/scans/$id-$datetime"
log_file="$scan_path/scan.log"

# Create directory structure
mkdir -p "$scan_path"/{subdomains,httpx,crawl,params,js,VulnScan/{nuclei,jaeles},responses,naabu_responses}
mkdir -p "$path"/{scope,lists}

# Initialize log file
touch "$log_file"
log "INFO" "Bug Bounty scan started for target: $id"
log "INFO" "Scan directory: $scan_path"

# Configuration variables
resolvers_file="$path/lists/resolvers.txt"
dns_wordlist_file="$path/lists/all.txt"
directory_wordlist_file="$path/lists/seclist"

# Set Token (REPLACE WITH YOUR ACTUAL TOKEN)
TOKEN="your_github_token_here"
interactsh_url="your_interactsh_url_here"

# Create sources file for theHarvester
sources_path="$path/lists"
mkdir -p "$sources_path"
cat <<EOF > "$path/sources.txt"
baidu
bufferoverun
crtsh
hackertarget
otx
projectdiscovery
rapiddns
sublist3r
threatcrowd
urlscan
virustotal
zoomeye
EOF

# Check for required files
if [ ! -f "$scope_path/roots.txt" ]; then
    log "ERROR" "The roots.txt file does not exist at $scope_path/roots.txt"
    exit 1
fi

log "INFO" "Starting scan against roots:"
cat "$scope_path/roots.txt" | tee -a "$log_file"
cp -v "$scope_path/roots.txt" "$scan_path/roots.txt"

# Function to run commands silently and check status
run_cmd() {
    local cmd="$1"
    local description="$2"
    
    log "INFO" "Starting $description..."
    
    if eval "$cmd" &>/dev/null; then
        log "INFO" "$description completed successfully"
        return 0
    else
        log "ERROR" "$description failed to execute"
        return 1
    fi
}

# Function to count lines and log results
count_and_log() {
    local file="$1"
    local tool_name="$2"
    
    if [ -f "$file" ]; then
        local count=$(wc -l < "$file" 2>/dev/null || echo "0")
        log "INFO" "$tool_name found $count items"
        return 0
    else
        log "WARN" "$tool_name output file not found: $file"
        return 1
    fi
}

# DNS Enumeration - Find Subdomains
subdomain_enum() {
    log "INFO" "=== Starting Subdomain Enumeration ==="
    
    # Initialize subs.txt
    touch "$scan_path/subs.txt"
    
    # haktrails
    log "INFO" "Starting Haktrails..."
    if command -v haktrails &> /dev/null; then
        if cat "$scan_path/roots.txt" | haktrails subdomains 2>/dev/null | anew "$scan_path/subs.txt" &>/dev/null; then
            count_and_log "$scan_path/subs.txt" "Haktrails"
        else
            log "WARN" "Haktrails failed to execute"
        fi
    else
        log "WARN" "Haktrails not installed"
    fi
    
    # subfinder
    log "INFO" "Starting Subfinder..."
    if command -v subfinder &> /dev/null; then
        while IFS= read -r domain; do
            if subfinder -d "$domain" -all -silent 2>/dev/null | anew "$scan_path/subs.txt" &>/dev/null; then
                log "DEBUG" "Subfinder completed for $domain"
            else
                log "WARN" "Subfinder failed for domain: $domain"
            fi
        done < "$scan_path/roots.txt"
        count_and_log "$scan_path/subs.txt" "Subfinder"
    else
        log "WARN" "Subfinder not installed"
    fi
    
    # shuffledns
    log "INFO" "Starting Shuffledns..."
    if command -v shuffledns &> /dev/null && [ -f "$path/lists/pry-dns.txt" ] && [ -f "$path/lists/resolvers.txt" ]; then
        if cat "$scan_path/roots.txt" | shuffledns -w "$path/lists/pry-dns.txt" -r "$path/lists/resolvers.txt" 2>/dev/null | anew "$scan_path/subs.txt" &>/dev/null; then
            count_and_log "$scan_path/subs.txt" "Shuffledns"
        else
            log "WARN" "Shuffledns failed to execute"
        fi
    else
        log "WARN" "Shuffledns not available or wordlists missing"
    fi
    
    # amass
    log "INFO" "Starting Amass..."
    if command -v amass &> /dev/null; then
        if amass enum -df "$scan_path/roots.txt" -o "$scan_path/amass_temp.txt" &>/dev/null; then
            cat "$scan_path/amass_temp.txt" | anew "$scan_path/subs.txt" &>/dev/null
            rm -f "$scan_path/amass_temp.txt"
            count_and_log "$scan_path/subs.txt" "Amass"
        else
            log "WARN" "Amass failed to execute"
        fi
    else
        log "WARN" "Amass not installed"
    fi
    
    # assetfinder
    log "INFO" "Starting assetfinder..."
    if command -v assetfinder &> /dev/null; then
        if cat "$scan_path/roots.txt" | assetfinder 2>/dev/null | anew "$scan_path/subs.txt" &>/dev/null; then
            count_and_log "$scan_path/subs.txt" "assetfinder"
        else
            log "WARN" "assetfinder failed to execute"
        fi
    else
        log "WARN" "assetfinder not installed"
    fi
    
    # chaos
    log "INFO" "Starting chaos..."
    if command -v chaos &> /dev/null; then
        if cat "$scan_path/roots.txt" | chaos -d -silent 2>/dev/null | anew "$scan_path/subs.txt" &>/dev/null; then
            count_and_log "$scan_path/subs.txt" "chaos"
        else
            log "WARN" "chaos failed to execute"
        fi
    else
        log "WARN" "chaos not installed"
    fi
    
    # crt.sh
    log "INFO" "Starting DNS enumeration with crt.sh..."
    while IFS= read -r domain; do
        if curl -s "https://crt.sh/?q=${domain}&output=json" 2>/dev/null | jq -r '.[]? | "\(.name_value)\n\(.common_name)"' 2>/dev/null | sort -u | anew "$scan_path/subs.txt" &>/dev/null; then
            log "DEBUG" "crt.sh completed for $domain"
        else
            log "WARN" "crt.sh failed for domain: $domain"
        fi
    done < "$scan_path/roots.txt"
    
    # theHarvester
    log "INFO" "Starting theHarvester enumeration..."
    if command -v theHarvester &> /dev/null; then
        while IFS= read -r domain; do
            while IFS= read -r source; do
                local output_file="$scan_path/${source}_${domain}.json"
                if theHarvester -d "$domain" -b "$source" -f "$output_file" &>/dev/null; then
                    if [ -f "$output_file" ]; then
                        jq -r '.hosts[]?' "$output_file" 2>/dev/null | cut -d':' -f1 | sort -u | anew "$scan_path/subs.txt" &>/dev/null
                    fi
                fi
                rm -f "$output_file"
            done < "$path/sources.txt"
        done < "$scan_path/roots.txt"
        count_and_log "$scan_path/subs.txt" "theHarvester"
    else
        log "WARN" "theHarvester not installed"
    fi
    
    local total_subs=$(wc -l < "$scan_path/subs.txt" 2>/dev/null || echo "0")
    log "INFO" "=== Subdomain Enumeration Complete: $total_subs total subdomains ==="
}

# Subdomain Permutation
subdomain_permutation() {
    log "INFO" "=== Starting Subdomain Permutation ==="
    
    if command -v alterx &> /dev/null; then
        if alterx -l "$scan_path/subs.txt" -o "$scan_path/subs_permuted.txt" &>/dev/null; then
            count_and_log "$scan_path/subs_permuted.txt" "alterx"
            
            # Resolve permuted subdomains
            if command -v dnsx &> /dev/null && [ -f "$path/lists/resolvers.txt" ]; then
                if dnsx -l "$scan_path/subs_permuted.txt" -r "$path/lists/resolvers.txt" -json -o "$scan_path/dns_permuted.json" &>/dev/null; then
                    if jq -r '.host' "$scan_path/dns_permuted.json" 2>/dev/null | anew "$scan_path/subs.txt" &>/dev/null; then
                        log "INFO" "Permuted subdomains resolved and added"
                    fi
                fi
            fi
        else
            log "WARN" "alterx failed to execute"
        fi
    else
        log "WARN" "alterx not installed"
    fi
    
    log "INFO" "=== Subdomain Permutation Complete ==="
}

# DNS Resolution
dns_resolution() {
    log "INFO" "=== Starting DNS Resolution ==="
    
    if command -v puredns &> /dev/null && [ -f "$path/lists/resolvers.txt" ]; then
        if puredns resolve "$scan_path/subs.txt" -r "$path/lists/resolvers.txt" -w "$scan_path/resolved.txt" &>/dev/null; then
            count_and_log "$scan_path/resolved.txt" "puredns"
            
            # Get detailed DNS info with dnsx
            if command -v dnsx &> /dev/null; then
                if dnsx -l "$scan_path/resolved.txt" -r "$path/lists/resolvers.txt" -json -o "$scan_path/dns.json" &>/dev/null; then
                    if jq -r '.a[]?' "$scan_path/dns.json" 2>/dev/null | anew "$scan_path/ips.txt" &>/dev/null; then
                        count_and_log "$scan_path/ips.txt" "IP addresses"
                    fi
                fi
            fi
        else
            log "WARN" "puredns failed to execute"
        fi
    else
        log "WARN" "puredns not available or resolvers list missing"
    fi
    
    log "INFO" "=== DNS Resolution Complete ==="
}

# Port Scanning
port_scanning() {
    log "INFO" "=== Starting Port Scanning ==="
    
    # Nmap scan
    if command -v nmap &> /dev/null && [ -f "$scan_path/ips.txt" ]; then
        if nmap -T4 -vv -iL "$scan_path/ips.txt" --top-ports 3000 -n --open -oX "$scan_path/nmap.xml" &>/dev/null; then
            log "INFO" "Nmap port scanning completed"
            
            # Process nmap results with tew and httpx
            if command -v tew &> /dev/null && command -v httpx &> /dev/null; then
                if tew -x "$scan_path/nmap.xml" -dnsx "$scan_path/dns.json" --vhost -o "$scan_path/hostport.txt" 2>/dev/null | httpx -sr -srd "$scan_path/responses" -json -o "$scan_path/http.json" &>/dev/null; then
                    log "INFO" "HTTP server discovery completed"
                    
                    # Extract URLs
                    if jq -r '.url' "$scan_path/http.json" 2>/dev/null | sed -e 's/:80$//g' -e 's/:443$//g' | sort -u > "$scan_path/http.txt"; then
                        count_and_log "$scan_path/http.txt" "HTTP URLs"
                    fi
                fi
            fi
        else
            log "WARN" "Nmap failed to execute"
        fi
    else
        log "WARN" "Nmap not available or no IPs to scan"
    fi
    
    # Naabu scan
    if command -v naabu &> /dev/null && [ -f "$scan_path/ips.txt" ]; then
        if naabu -l "$scan_path/ips.txt" -o "$scan_path/naabu_results.txt" &>/dev/null; then
            log "INFO" "Naabu scan completed"
            count_and_log "$scan_path/naabu_results.txt" "Naabu results"
            
            # Process naabu results
            if command -v dnsx &> /dev/null && [ -f "$path/lists/resolvers.txt" ]; then
                if dnsx -l "$scan_path/naabu_results.txt" -r "$path/lists/resolvers.txt" -json -o "$scan_path/naabu_dns.json" &>/dev/null; then
                    if command -v httpx &> /dev/null; then
                        if httpx -rl 4 -sr -srd "$scan_path/naabu_responses" -l "$scan_path/naabu_results.txt" -json -o "$scan_path/naabu_http.json" &>/dev/null; then
                            # Extract and merge URLs
                            jq -r '.url' "$scan_path/naabu_http.json" 2>/dev/null | sed -e 's/:80$//g' -e 's/:443$//g' | sort -u | anew "$scan_path/http.txt" &>/dev/null
                        fi
                    fi
                fi
            fi
        else
            log "WARN" "Naabu failed to execute"
        fi
    else
        log "WARN" "Naabu not available"
    fi
    
    log "INFO" "=== Port Scanning Complete ==="
}

# Crawling
crawling() {
    log "INFO" "=== Starting Web Crawling ==="
    
    touch "$scan_path/crawl.txt"
    
    # Gospider
    if command -v gospider &> /dev/null && [ -f "$scan_path/http.txt" ]; then
        if gospider -S "$scan_path/http.txt" --json 2>/dev/null | grep "{" | jq -r '.output?' 2>/dev/null | anew "$scan_path/crawl.txt" &>/dev/null; then
            log "INFO" "Gospider crawling completed"
        else
            log "WARN" "Gospider failed"
        fi
    else
        log "WARN" "Gospider not available"
    fi
    
    # Katana
    if command -v katana &> /dev/null && [ -f "$scan_path/http.txt" ]; then
        if katana -list "$scan_path/http.txt" -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -f qurl -jc -xhr -kf -fx -fs dn -ef woff,css,png,svg,jpg,woff2,jpeg,gif 2>/dev/null | anew "$scan_path/crawl.txt" &>/dev/null; then
            log "INFO" "Katana crawling completed"
        else
            log "WARN" "Katana failed"
        fi
    else
        log "WARN" "Katana not available"
    fi
    
    # GAU
    if command -v gau &> /dev/null && [ -f "$scan_path/resolved.txt" ]; then
        if cat "$scan_path/resolved.txt" | gau 2>/dev/null | anew "$scan_path/crawl.txt" &>/dev/null; then
            log "INFO" "GAU crawling completed"
        else
            log "WARN" "GAU failed"
        fi
    else
        log "WARN" "GAU not available"
    fi
    
    # Waybackurls
    if command -v waybackurls &> /dev/null && [ -f "$scan_path/resolved.txt" ]; then
        if cat "$scan_path/resolved.txt" | waybackurls 2>/dev/null | tee "$scan_path/waybackurls.txt" | anew "$scan_path/crawl.txt" &>/dev/null; then
            log "INFO" "Waybackurls completed"
        else
            log "WARN" "Waybackurls failed"
        fi
    else
        log "WARN" "Waybackurls not available"
    fi
    
    count_and_log "$scan_path/crawl.txt" "Total crawled URLs"
    log "INFO" "=== Web Crawling Complete ==="
}

# Parameter Discovery
parameters() {
    log "INFO" "=== Starting Parameter Discovery ==="
    
    touch "$scan_path/params.txt"
    
    # Arjun
    if command -v arjun &> /dev/null && [ -f "$scan_path/crawl.txt" ]; then
        if arjun -i "$scan_path/crawl.txt" -o "$scan_path/arjun_params.txt" &>/dev/null; then
            cat "$scan_path/arjun_params.txt" | anew "$scan_path/params.txt" &>/dev/null
            log "INFO" "Arjun parameter discovery completed"
        else
            log "WARN" "Arjun failed"
        fi
    else
        log "WARN" "Arjun not available"
    fi
    
    # ParamSpider (if available)
    if [ -f "$path/ParamSpider/paramspider.py" ] && [ -f "$scan_path/resolved.txt" ]; then
        if python3 "$path/ParamSpider/paramspider.py" --domain-file "$scan_path/resolved.txt" --output "$scan_path/paramspider.txt" &>/dev/null; then
            cat "$scan_path/paramspider.txt" | anew "$scan_path/params.txt" &>/dev/null
            log "INFO" "ParamSpider completed"
        else
            log "WARN" "ParamSpider failed"
        fi
    else
        log "WARN" "ParamSpider not available"
    fi
    
    count_and_log "$scan_path/params.txt" "Total parameters"
    log "INFO" "=== Parameter Discovery Complete ==="
}

# JavaScript Analysis
js_analysis() {
    log "INFO" "=== Starting JavaScript Analysis ==="
    
    mkdir -p "$scan_path/js"
    
    # Extract JS files from crawled URLs
    if [ -f "$scan_path/crawl.txt" ]; then
        cat "$scan_path/crawl.txt" | grep "\.js" | httpx -sr -srd "$scan_path/js" &>/dev/null
        log "INFO" "JavaScript files extracted"
        
        # SecretFinder
        if command -v secretfinder &> /dev/null; then
            if secretfinder -i "$scan_path/js" -o "$scan_path/secretfinder_results.txt" &>/dev/null; then
                log "INFO" "SecretFinder analysis completed"
            else
                log "WARN" "SecretFinder failed"
            fi
        fi
        
        # LinkFinder
        if command -v linkfinder &> /dev/null; then
            if linkfinder -i "$scan_path/js/*" -o "$scan_path/linkfinder_results.txt" &>/dev/null; then
                log "INFO" "LinkFinder analysis completed"
            else
                log "WARN" "LinkFinder failed"
            fi
        fi
    fi
    
    log "INFO" "=== JavaScript Analysis Complete ==="
}

# Vulnerability Scanning
vuln_scan() {
    log "INFO" "=== Starting Vulnerability Scanning ==="
    
    # Nuclei
    if command -v nuclei &> /dev/null && [ -f "$scan_path/http.txt" ]; then
        if nuclei -rl 4 -l "$scan_path/http.txt" -t cves -o "$scan_path/nuclei_results.txt" &>/dev/null; then
            log "INFO" "Nuclei vulnerability scanning completed"
            count_and_log "$scan_path/nuclei_results.txt" "Nuclei findings"
        else
            log "WARN" "Nuclei failed"
        fi
        
        # Nuclei fuzzing
        if [ -f "$scan_path/params.txt" ]; then
            if cat "$scan_path/params.txt" | grep "?" | httpx -silent -rl 4 > "$scan_path/nuclei_params.txt" 2>/dev/null; then
                if nuclei -t ~/nuclei-templates/dast/ -l "$scan_path/nuclei_params.txt" -o "$scan_path/nuclei_fuzzing.txt" &>/dev/null; then
                    log "INFO" "Nuclei fuzzing completed"
                    count_and_log "$scan_path/nuclei_fuzzing.txt" "Nuclei fuzzing findings"
                fi
            fi
        fi
    else
        log "WARN" "Nuclei not available"
    fi
    
    log "INFO" "=== Vulnerability Scanning Complete ==="
}

# XSS Testing
xss_testing() {
    log "INFO" "=== Starting XSS Testing ==="
    
    if [ -f "$scan_path/crawl.txt" ] && command -v gf &> /dev/null; then
        # Basic XSS testing
        if command -v qsreplace &> /dev/null && command -v httpx &> /dev/null; then
            cat "$scan_path/crawl.txt" | gf xss | httpx -silent -rl 4 | qsreplace '"><svg onload=confirm(1)>' > "$scan_path/xss_payloads.txt" 2>/dev/null
            log "INFO" "XSS payload URLs generated"
            count_and_log "$scan_path/xss_payloads.txt" "XSS test URLs"
        fi
        
        # Dalfox
        if command -v dalfox &> /dev/null; then
            cat "$scan_path/crawl.txt" | grep "=" | qsreplace -a | dalfox pipe -o "$scan_path/dalfox_results.txt" &>/dev/null
            log "INFO" "Dalfox XSS testing completed"
        fi
    fi
    
    log "INFO" "=== XSS Testing Complete ==="
}

# SSRF Testing
ssrf_testing() {
    log "INFO" "=== Starting SSRF Testing ==="
    
    if [ -f "$scan_path/crawl.txt" ] && command -v gf &> /dev/null && [ ! -z "$interactsh_url" ]; then
        cat "$scan_path/crawl.txt" | gf ssrf | httpx -silent -rl 4 | qsreplace "$interactsh_url" > "$scan_path/ssrf_payloads.txt" 2>/dev/null
        log "INFO" "SSRF payload URLs generated"
        count_and_log "$scan_path/ssrf_payloads.txt" "SSRF test URLs"
    fi
    
    log "INFO" "=== SSRF Testing Complete ==="
}

# SQL Injection Testing
sqli_testing() {
    log "INFO" "=== Starting SQL Injection Testing ==="
    
    if [ -f "$scan_path/crawl.txt" ] && command -v gf &> /dev/null; then
        cat "$scan_path/crawl.txt" | gf sqli > "$scan_path/sqli_urls.txt" 2>/dev/null
        
        if command -v sqlmap &> /dev/null && [ -s "$scan_path/sqli_urls.txt" ]; then
            sqlmap -m "$scan_path/sqli_urls.txt" --batch --banner --random-agent --output-dir="$scan_path/sqlmap" &>/dev/null
            log "INFO" "SQLMap testing completed"
        fi
    fi
    
    log "INFO" "=== SQL Injection Testing Complete ==="
}

# Generate final report
generate_report() {
    log "INFO" "=== Generating Final Report ==="
    
    local report_file="$scan_path/final_report.txt"
    
    cat > "$report_file" << EOF
# Bug Bounty Scan Report
## Target: $id
## Scan Date: $(date)
## Scan Directory: $scan_path

## Summary:
- Total Subdomains: $(wc -l < "$scan_path/subs.txt" 2>/dev/null || echo "0")
- Resolved Subdomains: $(wc -l < "$scan_path/resolved.txt" 2>/dev/null || echo "0")
- HTTP URLs: $(wc -l < "$scan_path/http.txt" 2>/dev/null || echo "0")
- Crawled URLs: $(wc -l < "$scan_path/crawl.txt" 2>/dev/null || echo "0")
- Parameters Found: $(wc -l < "$scan_path/params.txt" 2>/dev/null || echo "0")

## Files Generated:
$(find "$scan_path" -type f -name "*.txt" -o -name "*.json" | sort)

## Scan Log:
See: $log_file

EOF
    
    log "INFO" "Report generated: $report_file"
}

# Main execution
main() {
    log "INFO" "Starting comprehensive bug bounty scan"
    
    subdomain_enum
    subdomain_permutation
    dns_resolution
    port_scanning
    crawling
    parameters
    js_analysis
    vuln_scan
    xss_testing
    ssrf_testing
    sqli_testing
    generate_report
    
    log "INFO" "=== Bug Bounty Scan Complete ==="
    log "INFO" "Check the final report: $scan_path/final_report.txt"
    log "INFO" "All output files are in: $scan_path"
}

# Run the main function
main
