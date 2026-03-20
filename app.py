from flask import Flask, render_template, request, jsonify
import dns.resolver
import webbrowser
from threading import Timer
import logging
import sys
import os
import xml.etree.ElementTree as ET
import socket
import ssl
import datetime
from urllib.parse import urlparse

# --- 1. SETUP & PATHS ---
def resource_path(relative_path):
    """ Handles folder paths for both standard Python and the final EXE """
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

app = Flask(__name__, template_folder=resource_path('templates'), static_folder=resource_path('static'), static_url_path='/static')
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# --- 2. AUDIT & PARSING LOGIC ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/audit', methods=['POST'])
def audit():
    domain = request.json.get('domain', '').strip()
    if not domain:
        return jsonify({"error": "No domain provided"}), 400
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        resolver.timeout = 10.0
        resolver.lifetime = 15.0

        # SPF Detection & Analysis
        spf_rec, service, spf_v, spf_warnings = "No SPF record found", "Unknown / On-Premise", False, []
        try:
            q = resolver.resolve(domain, 'TXT')
            for r in q:
                txt = "".join([b.decode('utf-8') for b in r.strings])
                if "v=spf1" in txt:
                    spf_rec, spf_v = txt, True
                    if "outlook.com" in txt.lower(): service = "Microsoft 365"
                    elif "google.com" in txt.lower(): service = "Google Workspace"
                    elif "mimecast" in txt.lower(): service = "Mimecast"
                    
                    # SPF Analysis
                    if "~all" in txt.lower() and "-all" not in txt.lower():
                        spf_warnings.append("Using '~all' (softfail) instead of '-all' (hardfail) - less secure")
                    if "+all" in txt.lower():
                        spf_warnings.append("Using '+all' - allows ANY server to send email (very insecure!)")
                    if "include:" not in txt.lower() and "ip4:" not in txt.lower() and "ip6:" not in txt.lower():
                        spf_warnings.append("SPF record has no authorized servers - may be misconfigured")
                    if txt.count("include:") > 10:
                        spf_warnings.append("SPF record has too many includes - may hit lookup limit (10 max)")
                    break
        except: pass

        # MX Record Check
        mx_records = []
        try:
            q = resolver.resolve(domain, 'MX')
            for r in q:
                mx_records.append(str(r).split(" ")[1].rstrip("."))
        except: pass
        if not mx_records:
            mx_records = ["No MX records found"]

        # DKIM Record Check (TXT records for selectors)
        dkim_records = []
        dkim_selectors = [
            "default", "selector1", "selector2", "selector3",
            "key1", "key2", "dkim", "dkim1", "dkim2",
            "TEN", "TEN2", "google", "microsoft"
        ]
        for sel in dkim_selectors:
            try:
                q = resolver.resolve(f"{sel}._domainkey.{domain}", 'TXT', raise_on_no_answer=False)
                for r in q:
                    txt = str(r).strip('"')
                    if "v=DKIM1" in txt or "k=rsa" in txt:
                        dkim_records.append(f"{sel}._domainkey.{domain} -> {txt[:80]}...")
            except: pass
        if not dkim_records:
            dkim_records = ["No DKIM TXT records found"]

        # DMARC Detection
        dmarc_rec, rua, policy, dmarc_v = "No DMARC record found", "Not Configured", "Missing", False
        try:
            q = resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for r in q:
                txt = "".join([b.decode('utf-8') for b in r.strings])
                if "v=DMARC1" in txt:
                    dmarc_rec, dmarc_v = txt, True
                    if "rua=mailto:" in txt.lower():
                        rua = txt.lower().split("rua=mailto:")[1].split(";")[0]
                    if "p=quarantine" in txt.lower(): policy = "Quarantine"
                    elif "p=reject" in txt.lower(): policy = "Reject"
                    elif "p=none" in txt.lower(): policy = "None"
                    break
        except: pass

        cname_records = []
        dkim_selectors = [
            "default", "selector1", "selector2", "selector3",
            "key1", "key2", "dkim", "dkim1", "dkim2",
            "TEN", "TEN2", "mail", "google", "microsoft"
        ]
        
        common_cnames = [
            "mail", "smtp", "imap", "pop3", "webmail",
            "autodiscover", "autoconfig", "mta", "ftp",
            "www", "portal", "vle", "moodle", "canvas",
            "blackboard", "terms", "admin", "remote",
            "arbor", "arbor-sync", "sims", "sims-api",
            "capita", "Parent", "ParentPortal", "Staff",
            "school", "cloud", "api", "drive", "files",
            "office365", "o365", "outlook", "teams",
            "sharepoint", "sso", "id", "login", "auth"
        ]
        
        for sel in dkim_selectors:
            try:
                q = resolver.resolve(f"{sel}._domainkey.{domain}", 'CNAME', raise_on_no_answer=False)
                for r in q:
                    cname_records.append(f"{sel}._domainkey.{domain} -> {str(r)}")
            except: pass
        
        for sub in common_cnames:
            try:
                q = resolver.resolve(f"{sub}.{domain}", 'CNAME', raise_on_no_answer=False)
                for r in q:
                    cname_records.append(f"{sub}.{domain} -> {str(r)}")
            except: pass
        
        if not cname_records:
            cname_records = ["No CNAME records found"]

        return jsonify({
            "domain": domain, 
            "provider": service, 
            "report_to": rua, 
            "policy": policy, 
            "spf": {"record": spf_rec, "valid": spf_v, "warnings": spf_warnings}, 
            "mx": mx_records,
            "dkim": dkim_records,
            "dmarc": {"record": dmarc_rec, "valid": dmarc_v},
            "cname": cname_records
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/check_ssl', methods=['POST'])
def check_ssl():
    url = request.json.get('url', '').strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443
        
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        
        issuer = dict(x[0] for x in cert['issuer'])
        subject = dict(x[0] for x in cert['subject'])
        not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        not_before = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        days_until_expiry = (not_after - datetime.datetime.now()).days
        days_since_issue = (datetime.datetime.now() - not_before).days
        
        return jsonify({
            "url": url,
            "hostname": hostname,
            "port": port,
            "valid": True,
            "subject": subject.get('commonName', ''),
            "issuer": issuer.get('commonName', issuer.get('organizationName', 'Unknown')),
            "not_before": not_before.strftime('%Y-%m-%d'),
            "not_after": not_after.strftime('%Y-%m-%d'),
            "days_until_expiry": days_until_expiry,
            "days_since_issue": days_since_issue,
            "serial_number": cert.get('serialNumber', ''),
            "version": cert.get('version', '')
        })
    except socket.timeout:
        return jsonify({"error": "Connection timed out", "url": url}), 500
    except socket.error as e:
        return jsonify({"error": f"Connection error: {str(e)}", "url": url}), 500
    except Exception as e:
        return jsonify({"error": str(e), "url": url}), 500

@app.route('/parse_rua', methods=['POST'])
def parse_rua():
    if 'file' not in request.files: return jsonify({"error": "No file uploaded"}), 400
    try:
        file = request.files['file']
        tree = ET.parse(file)
        root = tree.getroot()
        report_data = []
        for record in root.findall('.//record'):
            ip = record.find('./row/source_ip').text
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = ip
            report_data.append({
                "source_server": hostname,
                "count": record.find('./row/count').text,
                "spf": record.find('./row/policy_evaluated/spf').text,
                "dkim": record.find('./row/policy_evaluated/dkim').text,
                "disposition": record.find('./row/policy_evaluated/disposition').text
            })
        return jsonify(report_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- 3. RUNNER ---
def open_browser():
    webbrowser.open('http://127.0.0.1:5000/')

if __name__ == '__main__':
    Timer(1.5, open_browser).start()
    app.run(host='127.0.0.1', port=5000, debug=False)