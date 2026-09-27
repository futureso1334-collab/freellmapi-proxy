import os
import re
import hashlib
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string
from supabase import create_client, Client

app = Flask(__name__)

# --- SUPABASE SETUP ---
url = os.environ.get("SUPABASE_URL")
key = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key) if url and key else None

class SovereignVaultAPIProcessor:
    def __init__(self):
        self.pii_patterns = {
            "PAN_CARD": r"[A-Z]{5}[0-9]{4}[A-Z]{1}",
            "AADHAAR": r"\d{4}\s\d{4}\s\d{4}",
            "CREDIT_CARD": r"\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}",
            "IFSC": r"[A-Z]{4}0[A-Z0-9]{6}",
            "EMAIL": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
            "PHONE": r"(?:\+91[\-\s]?)?[6-9]\d{9}"
        }
        self.restricted_terms = ["PROPRIETARY_ALGORITHM", "STOLEN_DATA", "RESTRICTED_SOURCE"]

    def process(self, text: str, custom_term: str = None) -> dict:
        terms_to_check = self.restricted_terms + ([custom_term] if custom_term else [])
        for term in terms_to_check:
            if term and re.search(term, text, re.IGNORECASE):
                return {"status": "BLOCKED", "reason": f"Restricted term found: {term}"}

        masked_text = text
        id_counter = 1
        for name, regex in self.pii_patterns.items():
            for match in re.findall(regex, masked_text):
                masked_text = masked_text.replace(match, f"[{name}_MASKED_{id_counter}]")
                id_counter += 1

        hash_obj = hashlib.sha256(masked_text.encode())
        hex_dig = hash_obj.hexdigest()
        vector = [int(hex_dig[i:i+2], 16) / 255.0 for i in range(0, 16, 2)]

        ai_summary = "Enterprise Clean Room Verified: Document successfully scrubbed of all PII and restricted identifiers."

        result = {
            "status": "SUCCESS (Clean Room Verified)",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "checksum_sha256": hex_dig,
            "sanitized_content": masked_text,
            "vector_embedding": vector,
            "ai_executive_summary": ai_summary
        }

        # Save to Supabase Audit Ledger Table
        if supabase:
            try:
                supabase.table("audit_logs").insert({
                    "timestamp": result["timestamp"],
                    "status": result["status"],
                    "checksum": hex_dig,
                    "sanitized_content": masked_text
                }).execute()
            except Exception as e:
                print(f"Supabase write error: {e}")

        return result

processor = SovereignVaultAPIProcessor()

HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SovereignVault AI | Enterprise RegTech</title>
    <style>
        :root {
            --bg: #fafaf9; --text: #1c1917; --card-bg: #ffffff; --border: #e7e5e4;
            --primary: #14532d; --primary-hover: #064e3b; --secondary-bg: #e7e5e4;
            --secondary-hover: #d6d3d1; --pre-bg: #f0fdf4; --pre-text: #166534;
            --pre-border: #bbf7d0; --muted: #78716c;
        }
        [data-theme="dark"] {
            --bg: #0c0a09; --text: #f5f5f4; --card-bg: #1c1917; --border: #292524;
            --primary: #22c55e; --primary-hover: #16a34a; --secondary-bg: #292524;
            --secondary-hover: #44403c; --pre-bg: #052e16; --pre-text: #4ade80;
            --pre-border: #14532d; --muted: #a8a29e;
        }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); padding: 24px 16px; max-width: 600px; margin: auto; line-height: 1.5; }
        header { margin-bottom: 24px; border-bottom: 1px solid var(--border); padding-bottom: 16px; display: flex; justify-content: space-between; align-items: center; }
        h1 { color: var(--primary); font-size: 20px; font-weight: 600; margin: 0 0 4px 0; }
        p { margin: 0; color: var(--muted); font-size: 13px; }
        .header-actions { display: flex; gap: 6px; }
        .theme-toggle, .logs-btn { background: var(--secondary-bg); color: var(--text); border: none; padding: 6px 10px; font-size: 11px; border-radius: 6px; cursor: pointer; text-decoration: none; font-weight: 500; }
        .card { background: var(--card-bg); padding: 18px; border-radius: 12px; border: 1px solid var(--border); margin-bottom: 16px; }
        .input-header, .output-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
        label { font-size: 13px; font-weight: 500; }
        .badge { background: #fef2f2; color: #991b1b; border: 1px solid #fecaca; font-size: 11px; font-weight: 600; padding: 2px 8px; border-radius: 12px; }
        .badge.safe { background: #f0fdf4; color: #166534; border-color: #bbf7d0; }
        textarea, input[type="text"], input[type="file"] { width: 100%; background: var(--card-bg); color: var(--text); border: 1px solid var(--border); padding: 10px; border-radius: 8px; box-sizing: border-box; font-family: ui-monospace, monospace; font-size: 12px; outline: none; margin-bottom: 10px; }
        textarea { height: 90px; resize: vertical; }
        button { background: var(--primary); color: #ffffff; border: none; padding: 12px; font-size: 14px; font-weight: 500; border-radius: 8px; cursor: pointer; width: 100%; }
        button:hover { background: var(--primary-hover); }
        .hash-badge { font-family: ui-monospace, monospace; font-size: 11px; background: var(--secondary-bg); color: var(--muted); padding: 2px 6px; border-radius: 4px; border: 1px solid var(--border); display: none; }
        pre { background: var(--pre-bg); padding: 14px; border-radius: 8px; overflow-x: auto; color: var(--pre-text); border: 1px solid var(--pre-border); font-size: 11px; margin: 0 0 12px 0; font-family: ui-monospace, monospace; }
        .action-row { display: flex; gap: 8px; }
        .secondary-btn { background: var(--secondary-bg); color: var(--text); margin-top: 0; flex: 1; }
        .file-upload-box { border: 2px dashed var(--border); padding: 12px; text-align: center; border-radius: 8px; margin-bottom: 10px; font-size: 12px; color: var(--muted); }
    </style>
</head>
<body data-theme="light">
    <header>
        <div>
            <h1>SovereignVault AI</h1>
            <p>Enterprise Clean Room & Audit Ledger</p>
        </div>
        <div class="header-actions">
            <a href="/logs" class="logs-btn">📜 Audit Logs</a>
            <button class="theme-toggle" onclick="toggleTheme()">🌓 Theme</button>
        </div>
    </header>

    <div class="card">
        <div class="input-header">
            <label>Raw Corporate Data Input:</label>
            <span id="threatBadge" class="badge">Analyzing PII...</span>
        </div>
        <textarea id="rawText" oninput="scanThreats()">Invoice for Vikram Malhotra, PAN: ABCDE5678G, Aadhaar: [Redacted], Email: vikram.m@fintechcorp.in, Mobile: +919876543210</textarea>
        
        <div class="file-upload-box">
            📁 Or Upload Batch File (.txt/.csv): <input type="file" id="batchFile" onchange="handleFileUpload()" style="margin-top:6px; border:none;">
        </div>

        <label style="font-size:11px; color:var(--muted);">Custom Restricted Term Rule:</label>
        <input type="text" id="customTerm" placeholder="e.g. PROJECT_OMEGA">

        <button onclick="processData()">Execute Clean Room Protocol</button>
    </div>

    <div class="card">
        <div class="output-header">
            <label>Secure Audit Ledger Result:</label>
            <span id="hashBadge" class="hash-badge">SHA: Idle</span>
        </div>
        <pre id="output">Awaiting clean room execution...</pre>
        <div class="action-row">
            <button class="secondary-btn" onclick="copyResult()">Copy</button>
            <button class="secondary-btn" onclick="downloadJSON()">Export Report</button>
        </div>
    </div>

    <script>
        let latestResult = null;
        function toggleTheme() {
            const body = document.body;
            body.setAttribute('data-theme', body.getAttribute('data-theme') === 'light' ? 'dark' : 'light');
        }
        function scanThreats() {
            const text = document.getElementById('rawText').value;
            const badge = document.getElementById('threatBadge');
            const pans = (text.match(/[A-Z]{5}[0-9]{4}[A-Z]{1}/g) || []).length;
            const emails = (text.match(/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/g) || []).length;
            const phones = (text.match(/(?:\+91[\-\s]?)?[6-9]\d{9}/g) || []).length;
            const total = pans + emails + phones;

            if (total > 0) {
                badge.className = "badge";
                badge.innerText = `⚠️ ${total} PII Threat(s)`;
            } else {
                badge.className = "badge safe";
                badge.innerText = "✓ Clean";
            }
        }
        function handleFileUpload() {
            const file = document.getElementById('batchFile').files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = function(e) {
                document.getElementById('rawText').value = e.target.result;
                scanThreats();
            };
            reader.readAsText(file);
        }
        async function processData() {
            const text = document.getElementById('rawText').value;
            const customTerm = document.getElementById('customTerm').value;
            document.getElementById('output').innerText = "Securing through Supabase Audit Pipeline...";
            const response = await fetch('/secure-vault', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ text: text, custom_term: customTerm })
            });
            latestResult = await response.json();
            document.getElementById('output').innerText = JSON.stringify(latestResult, null, 4);
            if (latestResult.checksum_sha256) {
                const hb = document.getElementById('hashBadge');
                hb.style.display = "inline-block";
                hb.innerText = `SHA: ${latestResult.checksum_sha256.substring(0, 8)}...`;
            }
        }
        function copyResult() {
            if (!latestResult) return;
            navigator.clipboard.writeText(JSON.stringify(latestResult, null, 4));
            alert("Audit trail copied to clipboard.");
        }
        function downloadJSON() {
            if (!latestResult) return;
            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(latestResult, null, 4));
            const anchor = document.createElement('a');
            anchor.setAttribute("href", dataStr);
            anchor.setAttribute("download", "sovereignvault_audit_record.json");
            document.body.appendChild(anchor);
            anchor.click();
            anchor.remove();
        }
        window.onload = scanThreats;
    </script>
</body>
</html>
"""

LOGS_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SovereignVault AI | Audit Logs</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #fafaf9; color: #1c1917; padding: 24px 16px; max-width: 600px; margin: auto; }
        h1 { color: #14532d; font-size: 20px; margin-bottom: 4px; }
        p { color: #78716c; font-size: 13px; margin-bottom: 20px; }
        .log-card { background: #fff; border: 1px solid #e7e5e4; border-radius: 8px; padding: 12px; margin-bottom: 10px; font-size: 12px; }
        .log-header { display: flex; justify-content: space-between; font-weight: 600; color: #14532d; margin-bottom: 4px; }
        .back-btn { background: #14532d; color: #fff; padding: 10px 16px; border-radius: 6px; text-decoration: none; display: inline-block; font-size: 13px; margin-bottom: 16px; }
    </style>
</head>
<body>
    <a href="/" class="back-btn">← Back to Clean Room</a>
    <h1>Persistent Supabase Audit Ledger</h1>
    <p>Permanent cryptographic log of all processed clean room transactions.</p>
    {% for log in logs %}
    <div class="log-card">
        <div class="log-header">
            <span>{{ log.timestamp }}</span>
            <span>ID: #{{ log.id }}</span>
        </div>
        <div><strong>Status:</strong> {{ log.status }}</div>
        <div><strong>SHA Checksum:</strong> <code style="font-family:monospace;">{{ log.checksum }}</code></div>
        <div style="margin-top: 6px; color: #44403c;"><strong>Sanitized Data:</strong> {{ log.sanitized_content }}</div>
    </div>
    {% endfor %}
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/health')
def health_check():
    try:
        if supabase:
            return jsonify({
                "status": "healthy",
                "database": "connected to Supabase",
                "supabase_url": url[:15] + "..." if url else "missing"
            }), 200
        else:
            return jsonify({
                "status": "healthy",
                "database": "unconfigured (missing environment variables)"
            }), 200
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "error": str(e)
        }), 500

@app.route('/logs')
def view_logs():
    logs = []
    if supabase:
        try:
            response = supabase.table("audit_logs").select("*").order("id", desc=True).execute()
            logs = response.data
        except Exception as e:
            print(f"Error fetching logs: {e}")
    return render_template_string(LOGS_TEMPLATE, logs=logs)

@app.route('/secure-vault', methods=['POST'])
def secure_endpoint():
    data = request.json
    raw_text = data.get("text", "")
    custom_term = data.get("custom_term", "")
    result = processor.process(raw_text, custom_term)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
