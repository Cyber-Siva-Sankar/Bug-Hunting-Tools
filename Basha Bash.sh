#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Function to print colored messages
print_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Display Banner
echo -e "${GREEN}----------------------------------------------------${NC}"
echo -e "${CYAN}    🌟 BAASHA - THE LEGENDARY MANICK BAASHA 🌟     ${NC}"
echo -e "${MAGENTA}  \"Naan oru dhadavai sonna, nooru dhadavai sonna madiri\"  ${NC}"
echo -e "${MAGENTA}       (I say it once, consider it said 100 times)        ${NC}"
echo -e "${GREEN}----------------------------------------------------${NC}\n"

# Check if a URL is provided
if [ -z "$1" ]; then
    print_error "Usage: $0 <url>"
    exit 1
fi

URL=$1
HOST=$(echo $URL | awk -F[/:] '{print $4}')

print_info "Starting information gathering for: $URL\n"

# 1. Ping to Find IP Address
print_info "Pinging the host to find its IP address..."
ping -c 1 $HOST &>/dev/null
if [ $? -eq 0 ]; then
    IP=$(ping -c 1 $HOST | grep "PING" | awk '{print $3}' | tr -d '()')
    print_success "IP Address: $IP\n"
else
    print_warning "Host is unreachable. Skipping IP discovery.\n"
fi

# 2. Application Fingerprinting (WhatWeb)
print_info "Identifying technologies used on the site (WhatWeb)..."
if command -v whatweb &>/dev/null; then
    whatweb_output=$(whatweb $URL)
    echo -e "${MAGENTA}--- WhatWeb Output ---${NC}\n$whatweb_output\n"
else
    print_warning "WhatWeb is not installed. Skipping technology identification.\n"
fi

# 3. WAF Detection (Wafw00f)
print_info "Detecting Web Application Firewall (WAF)..."
if command -v wafw00f &>/dev/null; then
    waf_output=$(wafw00f $URL)
    echo -e "${MAGENTA}--- WAF Detection Output ---${NC}\n$waf_output\n"
else
    print_warning "Wafw00f is not installed. Skipping WAF detection.\n"
fi

# 4. Subdomain Enumeration
print_info "Enumerating subdomains..."
subdomains=$(curl -s "https://crt.sh/?q=%.$HOST&output=json" | jq -r '.[].name_value' | sort -u)
if [ -n "$subdomains" ]; then
    echo -e "${MAGENTA}--- Subdomains Found ---${NC}\n$subdomains\n"
else
    print_warning "No subdomains found or the API did not respond.\n"
fi

# 5. JavaScript Analysis
print_info "Analyzing JavaScript files for potential endpoints..."
js_files=$(curl -s $URL | grep -Eo 'src="[^"]+\.js"' | cut -d'"' -f2)
if [ -n "$js_files" ]; then
    echo -e "${MAGENTA}--- JavaScript Files Found ---${NC}\n$js_files\n"
    for js in $js_files; do
        js_url=$(echo $js | grep -E '^http' || echo "$URL/$js")
        js_content=$(curl -s --max-time 10 "$js_url")
        echo -e "${MAGENTA}--- Analyzing: $js_url ---${NC}\n"
        echo "$js_content" | grep -Eo "(https?://[a-zA-Z0-9./?=_-]+|[a-zA-Z0-9_-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
    done
else
    print_warning "No JavaScript files found or could not be fetched.\n"
fi

# 6. Security Headers Check
print_info "Checking security headers..."
security_headers=$(curl -s -I --max-time 10 $URL | grep -i -E "Strict-Transport-Security|Content-Security-Policy|X-Frame-Options|X-Content-Type-Options|Referrer-Policy|Permissions-Policy")
if [ -n "$security_headers" ]; then
    echo -e "${MAGENTA}--- Security Headers ---${NC}\n$security_headers\n"
else
    print_warning "No security headers detected or the server did not respond in time.\n"
fi

# 7. CORS Misconfigurations
print_info "Checking for CORS misconfigurations..."
cors=$(curl -s -I -H "Origin: https://evil.com" --max-time 10 $URL | grep -i "Access-Control-Allow-Origin")
if [ -n "$cors" ]; then
    echo -e "${MAGENTA}--- CORS Policy ---${NC}\n$cors\n"
    if echo "$cors" | grep -q "*"; then
        print_warning "CORS misconfiguration detected: Wildcard allowed.\n"
    fi
else
    print_warning "No CORS headers detected or the server did not respond.\n"
fi

# 8. Clickjacking Detection
print_info "Checking for Clickjacking Protection..."
x_frame_options=$(curl -s -I --max-time 10 $URL | grep -i "X-Frame-Options")
if [ -n "$x_frame_options" ]; then
    print_success "Clickjacking protection detected (X-Frame-Options: $x_frame_options).\n"
else
    print_warning "No clickjacking protection detected.\n"
fi

# 9. TLS/SSL Configuration
print_info "Checking TLS/SSL settings..."
ssl_check=$(curl -s -I --insecure $URL | grep -i "Strict-Transport-Security")
if [ -n "$ssl_check" ]; then
    print_success "TLS/SSL settings are configured properly.\n"
else
    print_warning "No TLS/SSL settings or misconfigurations detected.\n"
fi

# 10. Open Redirection Check
print_info "Testing for open redirection vulnerabilities..."
open_redirect=$(curl -s -I --max-time 10 "$URL/redirect?url=http://evil.com")
if [ -n "$(echo $open_redirect | grep -i "Location")" ]; then
    print_success "Open redirection vulnerability found.\n"
else
    print_warning "No open redirection vulnerabilities detected.\n"
fi

# 11. Sitemap.xml URLs Check
print_info "Fetching Sitemap URLs only..."
sitemap_urls=$(curl -s "$URL/sitemap.xml" | grep -oP 'https?://[^/"]+' | sort -u)
if [ -n "$sitemap_urls" ]; then
    echo -e "${MAGENTA}--- Sitemap URLs ---${NC}\n$sitemap_urls\n"
else
    print_warning "No sitemap.xml URLs found or not accessible.\n"
fi

# 12. Server Banner Grabber
print_info "Grabbing server banner..."
server_banner=$(curl -s -I $URL | grep -i "Server")
if [ -n "$server_banner" ]; then
    print_success "Server Banner: $server_banner\n"
else
    print_warning "Server banner not found.\n"
fi

# 13. XSS Detection (if parameters exist)
print_info "Detecting XSS vulnerabilities (if parameters present)..."
params=$(echo $URL | grep -oP '[?&]') # Checks for parameters
if [ -n "$params" ]; then
    xss_scan=$(curl -s --data "param=<script>alert(1)</script>" $URL)
    if echo "$xss_scan" | grep -qi "alert"; then
        print_success "XSS vulnerability detected.\n"
    else
        print_warning "No XSS vulnerabilities found.\n"
    fi
else
    print_warning "No parameters found, skipping XSS scan.\n"
fi

# 14. HTML Injection Detection
print_info "Detecting HTML Injection vulnerabilities (if parameters present)..."
if [ -n "$params" ]; then
    html_injection=$(curl -s --data "param=<div>HTML Injection Test</div>" $URL)
    if echo "$html_injection" | grep -qi "<div>HTML Injection Test</div>"; then
        print_success "HTML Injection vulnerability detected.\n"
    else
        print_warning "No HTML Injection vulnerabilities found.\n"
    fi
else
    print_warning "No parameters found, skipping HTML Injection scan.\n"
fi

# 15. Nmap Scan (Including OS Detection)
print_info "Running Nmap scan (this may take a while)..."
if command -v nmap &>/dev/null; then
    nmap -A -T4 $HOST -oN nmap_report.txt
    print_success "Nmap scan completed. Check nmap_report.txt for details.\n"
else
    print_warning "Nmap is not installed. Skipping Nmap scan.\n"
fi

# 16. Directory Brute-Forcing (Dirb)
print_info "Running Dirb scan for hidden files and directories..."
if command -v dirb &>/dev/null; then
    dirb $URL -o dirb_report.txt
    print_success "Dirb scan completed. Check dirb_report.txt for details.\n"
else
    print_warning "Dirb is not installed. Skipping directory brute-forcing.\n"
fi

# 17. Robots.txt Check
print_info "Checking robots.txt for disallowed URLs..."
robots_txt=$(curl -s "$URL/robots.txt")
if [ -n "$robots_txt" ]; then
    print_success "robots.txt found:\n$robots_txt\n"
else
    print_warning "robots.txt not found or inaccessible.\n"
fi

# Summary
print_success "Information gathering completed for: $URL"
