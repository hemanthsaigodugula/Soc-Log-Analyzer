#!/usr/bin/env python3
# ------------------------------------------------------------
# SOC Log Analyzer — Flask Web App (Single File)
# ------------------------------------------------------------

import os
import re
from collections import defaultdict
from flask import Flask, request, render_template_string, jsonify

# ------------------------------------------------------------
# Initialize Flask
# ------------------------------------------------------------
app = Flask(__name__)

# ------------------------------------------------------------
# Regex Patterns
# ------------------------------------------------------------
IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
FAILED_LOGIN_RE = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
ACCEPTED_LOGIN_RE = re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>\S+)")
NEW_USER_RE = re.compile(r"(useradd|adduser)\s+(?P<user>\S+)")
SUDO_RE = re.compile(r"sudo: (?P<user>\S+):")
WGET_PIPE_RE = re.compile(r"(wget|curl).*(\|\s*sh)")
BASE64_RE = re.compile(r"base64 -d|base64 --decode")
REVERSE_SHELL_RE = re.compile(r"bash -i >& /dev/tcp|nc .* -e|python -c 'import socket'")
SCAN_RE = re.compile(r"\bnmap\b|\bmasscan\b|\bscan\b", re.IGNORECASE)

# ------------------------------------------------------------
# Rule weights
# ------------------------------------------------------------
RULE_WEIGHTS = {
    'bruteforce': 40,
    'successful_after_fail': 30,
    'new_user': 30,
    'suspicious_cmd': 25,
    'reverse_shell': 60,
    'sudo_unusual': 20,
    'scan_behavior': 35,
}

# ------------------------------------------------------------
# Human-friendly alert messages
# ------------------------------------------------------------
RULE_MESSAGES = {
    'bruteforce': (
        'Multiple failed SSH login attempts detected.',
        'Block this IP and enable SSH rate limits.'
    ),
    'successful_after_fail': (
        'Successful login after many failures — possible credential compromise.',
        'Investigate user activity and rotate credentials.'
    ),
    'new_user': (
        'A new system user was created.',
        'Verify if this was authorized.'
    ),
    'suspicious_cmd': (
        'Suspicious command detected: Remote download or base64 decode.',
        'Review system activity immediately.'
    ),
    'reverse_shell': (
        'Reverse shell pattern detected. HIGH RISK.',
        'Isolate the machine and investigate immediately.'
    ),
    'sudo_unusual': (
        'Unusual sudo usage.',
        'Check permissions and recent command history.'
    ),
    'scan_behavior': (
        'Port scanning behavior detected.',
        'Monitor and consider blocking the IP.'
    ),
}

# ------------------------------------------------------------
# Parse logs into list
# ------------------------------------------------------------
def parse_logs(text):
    return [line for line in text.splitlines() if line.strip()]

# ------------------------------------------------------------
# Analyze logs
# ------------------------------------------------------------
def analyze(parsed):
    findings = []
    ip_fail = defaultdict(int)
    ip_activity = defaultdict(int)
    success_after_fail = set()

    for line in parsed:
        # Count IP activity
        for ip in IP_RE.findall(line):
            ip_activity[ip] += 1

        # Failed login
        m = FAILED_LOGIN_RE.search(line)
        if m:
            ip_fail[m.group("ip")] += 1

        # Accepted login
        m2 = ACCEPTED_LOGIN_RE.search(line)
        if m2:
            ip = m2.group("ip")
            user = m2.group("user")
            if ip_fail[ip] >= 3:
                success_after_fail.add((ip, user))

        # New user
        m3 = NEW_USER_RE.search(line)
        if m3:
            findings.append({
                "rule": "new_user",
                "evidence": line,
                "user": m3.group("user")
            })

        # Sudo usage
        m4 = SUDO_RE.search(line)
        if m4:
            findings.append({
                "rule": "sudo_unusual",
                "evidence": line,
                "user": m4.group("user")
            })

        # Suspicious commands
        if WGET_PIPE_RE.search(line) or BASE64_RE.search(line):
            findings.append({"rule": "suspicious_cmd", "evidence": line})

        # Reverse shell
        if REVERSE_SHELL_RE.search(line):
            findings.append({"rule": "reverse_shell", "evidence": line})

        # Scan behavior keywords
        if SCAN_RE.search(line):
            findings.append({"rule": "scan_behavior", "evidence": line})

    # Bruteforce detection
    for ip, count in ip_fail.items():
        if count >= 5:
            findings.append({
                "rule": "bruteforce",
                "evidence": f"{count} failed attempts from {ip}",
                "ip": ip
            })

    # Successful after fails
    for ip, user in success_after_fail:
        findings.append({
            "rule": "successful_after_fail",
            "evidence": f"{user} logged in after many failures from {ip}",
            "ip": ip,
            "user": user
        })

    # Activity-based scanning
    for ip, count in ip_activity.items():
        if count >= 20:
            findings.append({
                "rule": "scan_behavior",
                "evidence": f"{count} mentions for IP {ip}",
                "ip": ip
            })

    # Final scoring
    total_score = 0
    report = []

    for f in findings:
        rule = f["rule"]
        score = RULE_WEIGHTS.get(rule, 10)
        total_score += score
        msg, reco = RULE_MESSAGES.get(rule, ("Suspicious activity detected.", "Investigate."))
        report.append({
            "rule": rule,
            "score": score,
            "message": msg,
            "evidence": f["evidence"],
            "recommendation": reco,
            "meta": f
        })

    if total_score >= 150:
        severity = "Critical"
    elif total_score >= 80:
        severity = "High"
    elif total_score >= 40:
        severity = "Medium"
    else:
        severity = "Low"

    return {
        "severity": severity,
        "total_score": total_score,
        "findings": report
    }

# ------------------------------------------------------------
# HTML template
# ------------------------------------------------------------
INDEX_HTML = """
<!doctype html>
<html>
<head>
<title>SOC Log Analyzer</title>
<style>
body{font-family:Arial;padding:20px;max-width:900px;margin:auto;}
textarea{width:100%;height:250px;font-family:monospace;padding:10px;}
.card{border:1px solid #ccc;padding:12px;border-radius:8px;margin-bottom:12px;}
pre{background:#f4f4f4;padding:10px;border-radius:5px;}
button{padding:10px 18px;background:#2563eb;color:white;border:none;border-radius:5px;}
</style>
</head>
<body>

<h1>SOC Log Analyzer</h1>
<p>Paste logs or upload a log file.</p>

<form method="POST" enctype="multipart/form-data">
<div class="card">
<textarea name="logtext" placeholder="Paste syslog/auth.log here..."></textarea>
</div>

<div class="card">
<input type="file" name="logfile">
</div>

<button type="submit">Analyze</button>
</form>

{% if summary %}
<hr>
<h2>Severity: {{summary['severity']}} (Score {{summary['total_score']}})</h2>

{% for f in summary['findings'] %}
<div class="card">
<b>{{f['message']}}</b>
<br/>Score: {{f['score']}}
<pre>{{f['evidence']}}</pre>
<b>Recommendation:</b> {{f['recommendation']}}
</div>
{% endfor %}
{% endif %}

</body>
</html>
"""

# ------------------------------------------------------------
# Flask Routes
# ------------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    summary = None

    if request.method == "POST":
        text = ""

        file = request.files.get("logfile")
        if file and file.filename:
            text = file.read().decode("utf-8", errors="ignore")
        else:
            text = request.form.get("logtext", "")

        parsed = parse_logs(text)
        summary = analyze(parsed)

    return render_template_string(INDEX_HTML, summary=summary)

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json(force=True)
    logs = data.get("logs", "")
    parsed = parse_logs(logs)
    return jsonify(analyze(parsed))

# ------------------------------------------------------------
# Run App
# ------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
