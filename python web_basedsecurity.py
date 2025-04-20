from flask import Flask, request, render_template_string, jsonify
import requests
from urllib.parse import urlparse
import uuid
from threading import Thread
from datetime import datetime, timedelta

app = Flask(__name__)

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced Web Vulnerability Scanner</title>
    <style>
        :root {
            --primary: #2c3e50;
            --secondary: #3498db;
            --danger: #e74c3c;
            --success: #2ecc71;
            --background: #f8f9fa;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            line-height: 1.6;
            background: var(--background);
            color: var(--primary);
        }

        .container {
            max-width: 1200px;
            margin: 2rem auto;
            padding: 0 1rem;
        }

        .header {
            text-align: center;
            padding: 2rem 0;
            background: var(--primary);
            color: white;
            border-radius: 10px;
            margin-bottom: 2rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        .scan-form {
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
        }

        #url-input {
            flex: 1;
            padding: 1rem;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 1rem;
            transition: border-color 0.3s ease;
        }

        #url-input:focus {
            outline: none;
            border-color: var(--secondary);
        }

        button {
            padding: 1rem 2rem;
            background: var(--secondary);
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            transition: transform 0.2s ease, background 0.3s ease;
        }

        button:hover {
            background: #2980b9;
            transform: translateY(-2px);
        }

        .scan-status {
            display: none;
            padding: 1rem;
            background: white;
            border-radius: 5px;
            margin-bottom: 2rem;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        }

        .progress-bar {
            height: 8px;
            background: #eee;
            border-radius: 4px;
            overflow: hidden;
            margin: 1rem 0;
        }

        .progress-fill {
            height: 100%;
            background: var(--secondary);
            width: 0%;
            transition: width 0.3s ease;
        }

        .results-section {
            background: white;
            border-radius: 10px;
            padding: 2rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
        }

        .vulnerability-card {
            border-left: 4px solid;
            margin: 1rem 0;
            padding: 1.5rem;
            background: white;
            border-radius: 5px;
            cursor: pointer;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .vulnerability-card:hover {
            transform: translateX(5px);
            box-shadow: 0 3px 8px rgba(0, 0, 0, 0.1);
        }

        .critical { border-color: var(--danger); }
        .high { border-color: #e67e22; }
        .medium { border-color: #f1c40f; }
        .low { border-color: var(--success); }

        .details {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
            margin-top: 1rem;
        }

        .risk-tag {
            display: inline-block;
            padding: 0.3rem 0.8rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: bold;
            text-transform: uppercase;
        }

        .critical-bg { background: var(--danger); color: black; }
        .high-bg { background: #e67e22; color: black; }
        .medium-bg { background: #f1c40f; color: black; }
        .low-bg { background: var(--success); color: black; }

        pre {
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 5px;
            overflow-x: auto;
            margin: 1rem 0;
        }

        .summary-card {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .summary-item {
            text-align: center;
            padding: 1.5rem;
            border-radius: 8px;
            background: white;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        }

        .error-message {
            color: var(--danger);
            padding: 1rem;
            background: #ffecec;
            border-radius: 5px;
            margin: 1rem 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Web Vulnerability Scanner</h1>
            <p>Comprehensive Security Assessment Tool</p>
        </div>

        <form class="scan-form" onsubmit="startScan(event)">
            <input type="url" id="url-input" placeholder="https://example.com" required>
            <button type="submit">Start Scan</button>
        </form>

        <div class="scan-status">
            <h3>Scan Progress</h3>
            <div class="progress-bar">
                <div class="progress-fill"></div>
            </div>
            <p class="status-text">Initializing scan...</p>
        </div>

        <div id="error-message" class="error-message" style="display: none;"></div>

        <div id="results-section" class="results-section" style="display: none;">
            <h2>Scan Summary</h2>
            <div class="summary-card" id="summary"></div>
            
            <h2>Detailed Findings</h2>
            <div id="results"></div>
        </div>
    </div>

    <script>
        function startScan(e) {
            e.preventDefault();
            const url = document.getElementById('url-input').value;
            const statusDiv = document.querySelector('.scan-status');
            const resultsSection = document.getElementById('results-section');
            const errorDiv = document.getElementById('error-message');
            
            // Reset UI
            statusDiv.style.display = 'block';
            resultsSection.style.display = 'none';
            errorDiv.style.display = 'none';
            updateProgress(0);

            fetch('/scan', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json'
                },
                body: `url=${encodeURIComponent(url)}`
            })
            .then(response => {
                if (!response.ok) {
                    return response.json().then(err => { throw err; });
                }
                return response.json();
            })
            .then(data => {
                if(data.scan_id) {
                    trackProgress(data.scan_id);
                } else if(data.error) {
                    showError(data.error);
                }
            })
            .catch(error => {
                showError(error.message || 'An error occurred during scan initialization');
            });
        }

        function updateProgress(percentage) {
            document.querySelector('.progress-fill').style.width = `${percentage}%`;
        }

        function trackProgress(scanId) {
            const statusText = document.querySelector('.status-text');
            const statusDiv = document.querySelector('.scan-status');
            const resultsSection = document.getElementById('results-section');
            
            const checkInterval = setInterval(() => {
                fetch(`/status/${scanId}`)
                .then(response => {
                    if (!response.ok) {
                        return response.json().then(err => { throw err; });
                    }
                    return response.json();
                })
                .then(data => {
                    if(data.status === 'completed') {
                        clearInterval(checkInterval);
                        showResults(data.results);
                        statusDiv.style.display = 'none';
                        resultsSection.style.display = 'block';
                    } else if(data.status === 'running') {
                        const progress = Math.min(90, data.progress || 0);
                        updateProgress(progress);
                        statusText.textContent = data.message || 'Scan in progress...';
                    } else if(data.error) {
                        clearInterval(checkInterval);
                        showError(data.error);
                    }
                })
                .catch(error => {
                    clearInterval(checkInterval);
                    showError(error.message || 'Error checking scan status');
                });
            }, 2000);
        }

        function showError(message) {
            const errorDiv = document.getElementById('error-message');
            errorDiv.textContent = message;
            errorDiv.style.display = 'block';
            document.querySelector('.scan-status').style.display = 'none';
        }

        function showResults(results) {
            updateProgress(100);
            
            // Update summary card
            const summary = {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0
            };

            results.forEach(vuln => {
                summary[vuln.risk.toLowerCase()]++;
            });

            document.getElementById('summary').innerHTML = `
                <div class="summary-item critical-bg">
                    <h3>${summary.critical}</h3>
                    <p>Critical</p>
                </div>
                <div class="summary-item high-bg">
                    <h3>${summary.high}</h3>
                    <p>High</p>
                </div>
                <div class="summary-item medium-bg">
                    <h3>${summary.medium}</h3>
                    <p>Medium</p>
                </div>
                <div class="summary-item low-bg">
                    <h3>${summary.low}</h3>
                    <p>Low</p>
                </div>
            `;

            // Add detailed results
            const resultsDiv = document.getElementById('results');
            resultsDiv.innerHTML = results.map(vuln => `
                <div class="vulnerability-card ${vuln.risk.toLowerCase()}" onclick="toggleDetails(this)">
                    <div class="risk-tag ${vuln.risk.toLowerCase()}-bg">
                        ${vuln.risk}
                    </div>
                    <h3>${vuln.name}</h3>
                    <p>${vuln.description}</p>
                    
                    <div class="details">
                        ${vuln.poc ? `<pre>PoC: ${vuln.poc}</pre>` : ''}
                        <p class="remediation"><strong>Remediation:</strong> ${vuln.remediation}</p>
                    </div>
                </div>
            `).join('');

            // Animate cards
            setTimeout(() => {
                document.querySelectorAll('.vulnerability-card').forEach((card, index) => {
                    card.style.opacity = 0;
                    card.style.transform = 'translateY(20px)';
                    setTimeout(() => {
                        card.style.opacity = 1;
                        card.style.transform = 'translateY(0)';
                    }, index * 100);
                });
            }, 500);
        }

        function toggleDetails(card) {
            const details = card.querySelector('.details');
            details.style.maxHeight = details.style.maxHeight ? null : `${details.scrollHeight}px`;
        }
    </script>
</body>
</html>
'''

# Vulnerability test functions
VULNERABILITIES = []

def register_vuln(name, risk, description, poc, remediation):
    def decorator(func):
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            return {
                'name': name,
                'risk': risk,
                'description': description,
                'poc': poc,
                'remediation': remediation,
                'found': result
            }
        VULNERABILITIES.append(wrapper)
        return wrapper
    return decorator

@register_vuln(
    name="SQL Injection",
    risk="CRITICAL",
    description="Potential SQL injection vulnerability detected",
    poc="' OR 1=1--",
    remediation="Use parameterized queries and prepared statements"
)
def test_sqli(url):
    test_url = f"{url}?id=1' OR 1=1--"
    try:
        r = requests.get(test_url, timeout=10)
        return "SQL syntax" in r.text or "error in your SQL" in r.text
    except:
        return False

@register_vuln(
    name="Cross-Site Scripting (XSS)",
    risk="HIGH",
    description="Potential XSS vulnerability detected",
    poc="<script>alert(1)</script>",
    remediation="Implement proper output encoding and input validation"
)
def test_xss(url):
    test_url = f"{url}?search=<script>alert(1)</script>"
    try:
        r = requests.get(test_url, timeout=10)
        return "<script>alert(1)</script>" in r.text
    except:
        return False

@register_vuln(
    name="Local File Inclusion (LFI)",
    risk="HIGH",
    description="Potential local file inclusion vulnerability",
    poc="../../../../etc/passwd",
    remediation="Validate and sanitize file path inputs"
)
def test_lfi(url):
    test_url = f"{url}?file=../../../../etc/passwd"
    try:
        r = requests.get(test_url, timeout=10)
        return "root:x:" in r.text
    except:
        return False

@register_vuln(
    name="Command Injection",
    risk="CRITICAL",
    description="Potential command injection vulnerability",
    poc="; ls -la",
    remediation="Use proper input validation and avoid system() calls"
)
def test_cmd_injection(url):
    test_url = f"{url}?input=; ls -la"
    try:
        r = requests.get(test_url, timeout=10)
        return "bin" in r.text and "etc" in r.text
    except:
        return False

@register_vuln(
    name="SSRF (Server-Side Request Forgery)",
    risk="HIGH",
    description="Potential SSRF vulnerability",
    poc="http://internal-server",
    remediation="Validate and restrict requested URLs"
)
def test_ssrf(url):
    try:
        test_url = f"{url}?url=http://169.254.169.254"
        r = requests.get(test_url, timeout=10)
        return "EC2" in r.text or "metadata" in r.text
    except:
        return False

@register_vuln(
    name="Open Redirect",
    risk="MEDIUM",
    description="Potential open redirect vulnerability",
    poc="?redirect=https://evil.com",
    remediation="Validate redirect URLs against allow list"
)
def test_open_redirect(url):
    test_url = f"{url}?redirect=https://google.com"
    try:
        r = requests.get(test_url, allow_redirects=False, timeout=10)
        return 300 <= r.status_code < 400 and "google.com" in r.headers.get('Location', '')
    except:
        return False

@register_vuln(
    name="XXE (XML External Entity)",
    risk="CRITICAL",
    description="Potential XXE vulnerability",
    poc="<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
    remediation="Disable external entities in XML parser"
)
def test_xxe(url):
    headers = {'Content-Type': 'application/xml'}
    data = '''<?xml version="1.0"?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <root><element>&xxe;</element></root>'''
    try:
        r = requests.post(url, data=data, headers=headers, timeout=10)
        return "root:x:" in r.text
    except:
        return False

@register_vuln(
    name="Insecure Headers",
    risk="MEDIUM",
    description="Missing security headers",
    poc="Check response headers",
    remediation="Implement security headers like CSP, HSTS, X-Content-Type"
)
def test_headers(url):
    try:
        r = requests.get(url, timeout=10)
        headers = r.headers
        missing = []
        if 'Content-Security-Policy' not in headers:
            missing.append("CSP")
        if 'Strict-Transport-Security' not in headers:
            missing.append("HSTS")
        if 'X-Content-Type-Options' not in headers:
            missing.append("X-Content-Type")
        return bool(missing)
    except:
        return False

# Scan management
scans_in_progress = {}
scan_results = {}
scan_timeout = timedelta(minutes=10)  # 10 minute timeout for scans

def cleanup_old_scans():
    now = datetime.now()
    for scan_id in list(scans_in_progress.keys()):
        scan_data = scans_in_progress[scan_id]
        if 'start_time' in scan_data and now - scan_data['start_time'] > scan_timeout:
            del scans_in_progress[scan_id]
            if scan_id in scan_results:
                del scan_results[scan_id]

def run_scan(scan_id, target_url):
    try:
        scans_in_progress[scan_id] = {
            'status': 'running',
            'progress': 0,
            'message': 'Starting scan...',
            'start_time': datetime.now()
        }
        
        results = []
        total_tests = len(VULNERABILITIES)
        
        for i, test in enumerate(VULNERABILITIES):
            # Check if scan was cancelled
            if scans_in_progress.get(scan_id, {}).get('status') == 'cancelled':
                break
                
            # Update progress
            progress = int((i + 1) / total_tests * 90)  # Leave 10% for completion
            scans_in_progress[scan_id] = {
                'status': 'running',
                'progress': progress,
                'message': f'Running test {i+1}/{total_tests}: {test.__name__}',
                'start_time': scans_in_progress[scan_id]['start_time']
            }
            
            # Run the test
            try:
                result = test(target_url)
                if result['found']:
                    results.append(result)
            except Exception as e:
                print(f"Error running test {test.__name__}: {str(e)}")
                continue
        
        # Store final results
        scan_results[scan_id] = results
        scans_in_progress[scan_id] = {
            'status': 'completed',
            'progress': 100,
            'message': 'Scan completed',
            'results': results
        }
    except Exception as e:
        scans_in_progress[scan_id] = {
            'status': 'error',
            'message': f'Scan failed: {str(e)}'
        }

# Flask routes
@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route('/scan', methods=['POST'])
def start_scan():
    cleanup_old_scans()
    
    target_url = request.form.get('url')
    if not target_url:
        return jsonify({'error': 'URL is required'}), 400
    
    if not target_url.startswith(('http://', 'https://')):
        target_url = f'http://{target_url}'
    
    # Validate URL
    try:
        parsed = urlparse(target_url)
        if not parsed.scheme or not parsed.netloc:
            return jsonify({'error': 'Invalid URL format'}), 400
    except:
        return jsonify({'error': 'Invalid URL format'}), 400
    
    # Create a new scan
    scan_id = str(uuid.uuid4())
    scans_in_progress[scan_id] = {
        'status': 'queued',
        'progress': 0,
        'message': 'Scan queued',
        'start_time': datetime.now()
    }
    
    # Start scan in background
    Thread(target=run_scan, args=(scan_id, target_url)).start()
    
    return jsonify({'scan_id': scan_id})

@app.route('/status/<scan_id>')
def scan_status(scan_id):
    cleanup_old_scans()
    
    if scan_id not in scans_in_progress:
        return jsonify({'error': 'Scan not found'}), 404
    
    status = scans_in_progress[scan_id]
    
    if status.get('status') == 'completed':
        status['results'] = scan_results.get(scan_id, [])
    
    return jsonify(status)

@app.route('/cancel/<scan_id>', methods=['POST'])
def cancel_scan(scan_id):
    if scan_id in scans_in_progress:
        scans_in_progress[scan_id]['status'] = 'cancelled'
        return jsonify({'status': 'cancelled'})
    return jsonify({'error': 'Scan not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)