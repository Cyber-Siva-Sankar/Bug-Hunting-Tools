# BASHA Bash Script

## Overview

The BAASHA Bash Script is a comprehensive tool designed for web application security testing and information gathering. It automates various tasks to help identify vulnerabilities and security misconfigurations in websites and web applications.

---

## Features

- IP Address Discovery
- Application Fingerprinting
- WAF Detection
- Subdomain Enumeration
- JavaScript Analysis
- Security Headers Check
- CORS Misconfigurations
- Clickjacking Detection
- TLS/SSL Configuration
- Open Redirection Check
- Sitemap.xml URLs Check
- Server Banner Grabber
- XSS Detection
- HTML Injection Detection
- Nmap Scan
- Directory Brute-Forcing (Dirb)
- Robots.txt Check

---

## Installation

### Prerequisites

- A Linux-based system (Ubuntu, Debian, etc.)
- Bash Shell

### Steps to Install

1. **Clone the repository**:

   ```bash
   git clone https://github.com/your-repository/baasha-script.git
   cd baasha-script

2. **Install Dependencies**:

   ```bash
   pip install -r requirements.txt

3. **Make the script executable**:

   ```bash
   chmod +x baasha.sh 
   ```  
**Running the BAASHA Bash Script**

**Usage**
   ```bash
   ./baasha.sh <URL>
   ```
**Example**
   ```bash
   ./baasha.sh https://example.com   
   ```
### Features Explanation

  - IP Address Discovery: Pings the host to find its IP address.
  - Application Fingerprinting: Identifies technologies used on the site using WhatWeb.
  - WAF Detection: Detects Web Application Firewalls using Wafw00f.
  - Subdomain Enumeration: Enumerates subdomains.
  - JavaScript Analysis: Analyzes JavaScript files for endpoints.
  - Security Headers Check: Checks for security headers such as HSTS, CSP, etc.
  - CORS Misconfigurations: Detects CORS misconfigurations.
  - Clickjacking Detection: Checks for clickjacking protection using X-Frame-Options.
  - TLS/SSL Configuration: Verifies TLS/SSL settings.
  - Open Redirection Check: Tests for open redirection vulnerabilities.
  - Sitemap.xml URLs Check: Retrieves and verifies URLs from sitemap.xml.
  - Server Banner Grabber: Grabs the server banner information.
  - XSS Detection: Detects XSS vulnerabilities if parameters exist.
  - HTML Injection Detection: Detects HTML injection vulnerabilities if parameters exist.
  - Nmap Scan: Performs a comprehensive network scan.
  - Directory Brute-Forcing: Runs a Dirb scan for hidden directories.
  - Robots.txt Check: Checks the robots.txt file for disallowed URLs.

### Note

   It's a Combined tool which help you to find the information about your target, instead of using one by one tool you can directly run it, 

   Happy Hacking ;)
    
