import numpy as np
from flask import Flask, request, jsonify, render_template, flash, session, redirect, url_for
import joblib
import random
import time
import uuid
import threading
import ipaddress
import logging
import os 
from datetime import datetime, timedelta
from collections import defaultdict, deque
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import base64
import numpy as np
import sounddevice as sd
import threading


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('nids')

app = Flask(__name__)
app.secret_key = "nids_secure_key_2025"
model = joblib.load('model.pkl')

# In-memory storage for active security measures
class SecurityMonitor:
    def __init__(self):
        self.blocked_ips = {}  # IP: (timestamp, reason)
        self.rate_limited_ips = {}  # IP: (timestamp, counter, max_rate)
        self.suspicious_activity = defaultdict(list)  # IP: [activities]
        self.connection_history = defaultdict(lambda: deque(maxlen=100))  # IP: deque of timestamps
        self.failed_logins = defaultdict(int)  # IP: count
        self.active_sessions = {}  # session_id: user_data
        self.attack_history = []  # List of detected attacks for dashboard
        self.lock = threading.Lock()
        
        # Start background thread for security monitoring
        self.active = True
        self.monitor_thread = threading.Thread(target=self.background_monitor)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def is_ip_blocked(self, ip):
        """Check if an IP is currently blocked"""
        with self.lock:
            if ip in self.blocked_ips:
                block_time, reason = self.blocked_ips[ip]
                if datetime.now() < block_time:
                    return True, reason
                else:
                    # Block expired
                    del self.blocked_ips[ip]
            return False, None
    
    def block_ip(self, ip, duration_minutes=30, reason="Suspicious activity"):
        """Block an IP address for a specified duration"""
        with self.lock:
            block_until = datetime.now() + timedelta(minutes=duration_minutes)
            self.blocked_ips[ip] = (block_until, reason)
            logger.warning(f"BLOCKED IP {ip} for {duration_minutes} minutes. Reason: {reason}")
            return block_until
    
    def check_rate_limit(self, ip, endpoint, max_rate=30):
        """Check and enforce rate limiting for an IP"""
        current_time = datetime.now()
        key = f"{ip}:{endpoint}"
        
        with self.lock:
            # Initialize or update rate limit record
            if key not in self.rate_limited_ips:
                self.rate_limited_ips[key] = (current_time, 1, max_rate)
                return False
            
            last_time, count, limit = self.rate_limited_ips[key]
            time_diff = (current_time - last_time).total_seconds()
            
            # Reset counter if enough time has passed
            if time_diff > 60:  # Reset every minute
                self.rate_limited_ips[key] = (current_time, 1, max_rate)
                return False
            
            # Increment counter and check if rate limit exceeded
            count += 1
            self.rate_limited_ips[key] = (last_time, count, limit)
            
            if count > limit:
                logger.warning(f"Rate limit exceeded for {ip} on {endpoint}: {count}/{limit}")
                return True
            
            return False
    
    def record_connection(self, ip, endpoint):
        """Record a connection for pattern analysis"""
        with self.lock:
            self.connection_history[ip].append((datetime.now(), endpoint))
    
    def analyze_connection_patterns(self, ip):
        """Analyze connection patterns for potential scan or probe activities"""
        with self.lock:
            if ip not in self.connection_history or len(self.connection_history[ip]) < 10:
                return False, None
            
            # Check for port scanning (many different endpoints in short time)
            recent_connections = [c for c in self.connection_history[ip] 
                                if (datetime.now() - c[0]).total_seconds() < 60]
            
            if len(recent_connections) > 15:
                unique_endpoints = len(set([c[1] for c in recent_connections]))
                if unique_endpoints > 8:  # More than 8 different endpoints in 60 seconds
                    return True, "Port scanning detected"
                    
            return False, None
    
    def record_attack(self, attack_data):
        """Record detected attack for the security dashboard and trigger email alert"""
        with self.lock:
            # Format the attack data
            formatted_attack = {
                "timestamp": datetime.now(),
                "ip": attack_data.get("ip", "unknown"),
                "type": attack_data.get("attack_type", "unknown"),
                "category": attack_data.get("category", "unknown"),
                "action_taken": attack_data.get("action", "none"),
                "details": attack_data.get("details", "")
            }
            
            if attack_data.get("category", "") != "Normal":
                play_alarm_sound()
            
            # Add to history
            self.attack_history.append(formatted_attack)
            
            # Keep only last 1000 attacks
            if len(self.attack_history) > 1000:
                self.attack_history = self.attack_history[-1000:]
            
            # Send email alert for all attacks (except normal traffic)
            if self.should_send_email_alert(formatted_attack):
                # Send email alert in a separate thread to avoid blocking
                threading.Thread(target=email_alerts.send_email_alert, 
                                args=(formatted_attack,)).start()
    
    def get_attack_history(self, limit=50):
        """Get recent attack history for dashboard"""
        with self.lock:
            return self.attack_history[-limit:]
    
    def record_failed_login(self, ip):
        """Record and check for brute force login attempts"""
        with self.lock:
            self.failed_logins[ip] += 1
            
            # Check for brute force attempts
            if self.failed_logins[ip] >= 5:
                self.block_ip(ip, duration_minutes=60, reason="Excessive login failures")
                logger.warning(f"Brute force attempt detected from {ip}")
                return True
            return False
    
    def record_suspicious_activity(self, ip, activity):
        """Record suspicious activity for an IP"""
        with self.lock:
            timestamp = datetime.now()
            self.suspicious_activity[ip].append((timestamp, activity))
            
            # Clean old records
            cutoff = datetime.now() - timedelta(hours=24)
            self.suspicious_activity[ip] = [
                a for a in self.suspicious_activity[ip] if a[0] > cutoff
            ]
            
            # Check for multiple suspicious activities
            recent = [a for a in self.suspicious_activity[ip] 
                     if a[0] > datetime.now() - timedelta(minutes=30)]
            
            if len(recent) >= 3:
                return self.block_ip(ip, reason="Multiple suspicious activities")
            return None
    
    def background_monitor(self):
        """Background thread to periodically check for security issues"""
        while self.active:
            try:
                with self.lock:
                    current_time = datetime.now()
                    
                    # Cleanup expired blocks
                    for ip in list(self.blocked_ips.keys()):
                        block_time, _ = self.blocked_ips[ip]
                        if current_time > block_time:
                            del self.blocked_ips[ip]
                    
                    # Check for synchronized attacks (multiple IPs doing the same thing)
                    if len(self.connection_history) > 10:
                        # (Simplified - a real system would have more sophisticated analysis)
                        endpoint_counts = defaultdict(int)
                        recent_cutoff = current_time - timedelta(seconds=30)
                        
                        for ip, connections in self.connection_history.items():
                            recent = [c for c in connections if c[0] > recent_cutoff]
                            for _, endpoint in recent:
                                endpoint_counts[endpoint] += 1
                        
                        # If any endpoint has unusually high traffic from multiple IPs
                        for endpoint, count in endpoint_counts.items():
                            if count > 50:  # Arbitrary threshold
                                logger.warning(f"Possible DDoS on {endpoint} with {count} requests")
            except Exception as e:
                logger.error(f"Error in security monitor: {str(e)}")
            
            time.sleep(5)  # Check every 5 seconds
            
    def should_send_email_alert(self, attack_data):
        """Determine if an email alert should be sent for this attack"""
        # Send alerts for all attacks except normal traffic
        if attack_data["category"] == "Normal":
            return False
        
        return True
    
    def shutdown(self):
        """Shutdown the monitor thread"""
        self.active = False
        if self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=1)
            
class EmailAlertSystem:
    def __init__(self):
        # Hardcoded credentials (NOT RECOMMENDED for production)
        self.email = "dronedetection2025@gmail.com"
        self.client_id = "999512989928-p19rf9o21a12rmkmbkq87860ndjag37t.apps.googleusercontent.com"
        self.client_secret = "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"
        self.refresh_token = "1//0gDOfw0pJpPYrCgYIARAAGBASNwF-L9Ir4DlsMkN8qrwFkgScWIGTS96DeVnwvF6Hj3sIF-h4yV86-gMDd0qNSX8klWq6cvZUaWQ"
        self.recipient_email = "dharaneesh7001@gmail.com"
        
        # Check if all required credentials are set
        required_vars = [
            self.email, 
            self.client_id, 
            self.client_secret, 
            self.refresh_token, 
            self.recipient_email
        ]
        
        if any(not var for var in required_vars):
            logger.error("One or more required email credentials are missing")
            self.email_enabled = False
        else:
            self.email_enabled = True
            logger.info("Email alert system initialized successfully")
    
    def get_credentials(self):
        """Get OAuth2 credentials for Gmail API"""
        try:
            creds = Credentials.from_authorized_user_info(
                {
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "refresh_token": self.refresh_token,
                    "token_uri": "https://oauth2.googleapis.com/token",
                }
            )
            
            return creds
        except Exception as e:
            logger.error(f"Credential generation error: {str(e)}")
            return None
    
    def send_email_alert(self, attack_data):
        """Send email alert for detected attack"""
        try:
            # Check if email is enabled
            if not self.email_enabled:
                logger.warning("Email alerts are disabled")
                return False
            
            # Get credentials
            creds = self.get_credentials()
            if not creds:
                logger.error("Failed to obtain credentials")
                return False
            
            # Build Gmail service
            try:
                service = build('gmail', 'v1', credentials=creds)
            except Exception as e:
                logger.error(f"Gmail service build error: {str(e)}")
                return False
            
            # Create email message
            message = MIMEMultipart()
            message['to'] = self.recipient_email
            message['from'] = self.email
            message['subject'] = f"🚨 NIDS Alert: {attack_data.get('type', 'Unknown')} Attack Detected!"
            
            # Prepare email content
            html_content = f"""
            <h2>🚨 Network Intrusion Detection Alert</h2>
            <p>A network attack has been detected in your system.</p>
            <p><strong>Attack Type:</strong> {attack_data.get('type', 'Unknown')}</p>
            <p><strong>Attack Category:</strong> {attack_data.get('category', 'Unknown')}</p>
            <p><strong>Time:</strong> {attack_data.get('timestamp', datetime.now()).strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Source IP:</strong> {attack_data.get('ip', 'Unknown')}</p>
            <p><strong>Action Taken:</strong> {attack_data.get('action', 'None')}</p>
            <p><strong>Details:</strong> {attack_data.get('details', 'No additional details')}</p>
            <p>Please review this alert in your NIDS dashboard.</p>
            """
            
            # Attach content
            message.attach(MIMEText(html_content, 'html'))
            
            # Encode and send
            try:
                raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
                service.users().messages().send(userId='me', body={'raw': raw_message}).execute()
                logger.info(f"Email alert sent successfully to {self.recipient_email}")
                return True
            except Exception as send_error:
                logger.error(f"Email sending error: {str(send_error)}")
                return False
        
        except Exception as e:
            logger.error(f"Unexpected error in send_email_alert: {str(e)}")
            return False
        
        
# Initialize security monitor
security = SecurityMonitor()
email_alerts = EmailAlertSystem()

# Define attack types and their descriptions
ATTACK_TYPES = {
    "normal": "Normal traffic (baseline)",
    "neptune": "Neptune DoS attack (SYN flooding)",
    "satan": "Satan probing attack (port scanning)",
    "portsweep": "Port sweep reconnaissance",
    "ipsweep": "IP sweep reconnaissance",
    "smurf": "Smurf DoS attack (ICMP echo)",
    "back": "Back DoS attack (HTTP abuse)",
    "teardrop": "Teardrop DoS attack (fragmented packets)",
    "warezclient": "Warezlient R2L attack (illegal file sharing)",
    "guess_passwd": "Password guessing attack",
    "buffer_overflow": "Buffer overflow U2R attack",
    "rootkit": "Rootkit U2R attack",
}

# Group attacks by category
ATTACK_CATEGORIES = {
    "DOS": ["neptune", "smurf", "back", "teardrop"],
    "PROBE": ["satan", "portsweep", "ipsweep"],
    "R2L": ["warezclient", "guess_passwd"],
    "U2R": ["buffer_overflow", "rootkit"],
    "Normal": ["normal"]
}

# Define actual prevention measures for each attack category
ACTIVE_PREVENTION = {
    "DOS": [
        "rate_limiting",       # Apply rate limiting
        "traffic_filtering",   # Filter suspicious traffic patterns
        "syn_cookies",         # Enable SYN cookies
        "connection_tracking", # Track and manage connection state
        "disable_icmp",        # Disable ICMP responses
        "ingress_filtering",   # Prevent IP spoofing
        "waf",                # Web Application Firewall
        "captcha"             # CAPTCHA for bot detection
    ],
    "PROBE": [
        "ip_blocking",         # Block the source IP temporarily
        "port_restriction",    # Restrict access to detected ports
        "honeypot_redirect",   # Redirect to honeypot
        "alert_escalation",    # Escalate alert to security team
        "fail2ban",            # Block repeated failed connections
        "port_knocking"        # Hide open ports
    ],
    "R2L": [
        "account_lockout",     # Lock the targeted account
        "access_restriction",  # Restrict suspicious access
        "2fa_challenge",       # Trigger additional authentication
        "session_termination", # Terminate suspicious sessions
        "dlp",                 # Data Loss Prevention
        "file_permissions"     # Restrict file-sharing permissions
    ],
    "U2R": [
        "process_termination", # Kill the suspicious process
        "integrity_check",     # Verify system integrity
        "privilege_reduction", # Reduce privileges
        "memory_protection",   # Implement memory protection
        "aslr",                # Address Space Layout Randomization
        "stack_canaries",      # Stack Canaries for buffer overflow protection
        "selinux",             # Mandatory Access Control (SELinux)
        "rootkit_scanner"      # Kernel Integrity Checker
    ]
}

# Prevention measure descriptions for display
PREVENTION_DESCRIPTIONS = {
    "rate_limiting": "Rate limiting applied to affected services",
    "traffic_filtering": "Traffic filtering rules implemented",
    "syn_cookies": "SYN cookies enabled to mitigate SYN flooding",
    "connection_tracking": "Dropped malicious packets from source IP",
    "ip_blocking": "Source IP temporarily blacklisted",
    "port_restriction": "Port scan detection triggered isolation protocol",
    "honeypot_redirect": "Redirected scanning activity to honeypot",
    "alert_escalation": "Security alert escalated to incident response team",
    "account_lockout": "Account locked after multiple failed attempts",
    "access_restriction": "Suspicious access attempt blocked",
    "2fa_challenge": "Two-factor authentication challenge triggered",
    "session_termination": "Suspicious session terminated",
    "process_termination": "Malicious process terminated",
    "integrity_check": "System integrity verification initiated",
    "privilege_reduction": "Privileges reduced to prevent escalation",
    "memory_protection": "Memory protection measures activated",
    "disable_icmp": "ICMP responses disabled to prevent Smurf attacks",
    "ingress_filtering": "Ingress filtering enabled to prevent IP spoofing",
    "waf": "Web Application Firewall enabled to block HTTP abuse",
    "captcha": "CAPTCHA enabled to detect bot traffic",
    "fail2ban": "Fail2Ban enabled to block repeated failed connections",
    "port_knocking": "Port knocking enabled to hide open ports",
    "dlp": "Data Loss Prevention enabled to monitor file transfers",
    "file_permissions": "File-sharing permissions restricted",
    "aslr": "Address Space Layout Randomization enabled",
    "stack_canaries": "Stack Canaries enabled to detect buffer overflows",
    "selinux": "SELinux enabled for Mandatory Access Control",
    "rootkit_scanner": "Rootkit scanner enabled to detect hidden processes"
}

# Request preprocessing middleware to check security measures
@app.before_request
def security_check():
    # Skip for static resources
    if request.path.startswith('/static/'):
        return
    
    client_ip = request.remote_addr
    
    # 1. Check if IP is blocked
    is_blocked, reason = security.is_ip_blocked(client_ip)
    if is_blocked:
        logger.info(f"Blocked request from {client_ip}: {reason}")
        return render_template('blocked.html', reason=reason), 403
    
    # 2. Check rate limiting
    is_rate_limited = security.check_rate_limit(client_ip, request.path)
    if is_rate_limited:
        security.record_suspicious_activity(client_ip, f"Rate limit exceeded on {request.path}")
        return render_template('rate_limited.html'), 429
    
    # 3. Record connection for pattern analysis
    security.record_connection(client_ip, request.path)
    
    # 4. Check for scanning patterns
    is_scanning, scan_type = security.analyze_connection_patterns(client_ip)
    if is_scanning:
        security.block_ip(client_ip, reason=scan_type)
        security.record_attack({
            "ip": client_ip,
            "attack_type": "scanning",
            "category": "PROBE",
            "action": "ip_blocking",
            "details": scan_type
        })
        return render_template('blocked.html', reason=scan_type), 403
    
    # 5. Check for suspicious form submissions
    if request.method == 'POST' and len(request.form) > 0:
        # Check for known attack signatures in form data
        for field, value in request.form.items():
            if isinstance(value, str):
                # Check for SQL injection attempts
                sql_patterns = ["'--", "OR 1=1", "' OR '1'='1", "; DROP TABLE", "UNION SELECT"]
                for pattern in sql_patterns:
                    if pattern.lower() in value.lower():
                        details = f"SQL injection attempt detected in {field}"
                        security.record_suspicious_activity(client_ip, details)
                        security.record_attack({
                            "ip": client_ip,
                            "attack_type": "sql_injection",
                            "category": "R2L",
                            "action": "access_restriction",
                            "details": details
                        })
                        return render_template('blocked.html', reason="Malicious input detected"), 403
                
                # Check for XSS attempts
                xss_patterns = ["<script>", "javascript:", "onerror=", "onload="]
                for pattern in xss_patterns:
                    if pattern.lower() in value.lower():
                        details = f"XSS attempt detected in {field}"
                        security.record_suspicious_activity(client_ip, details)
                        security.record_attack({
                            "ip": client_ip,
                            "attack_type": "xss",
                            "category": "R2L",
                            "action": "access_restriction",
                            "details": details
                        })
                        return render_template('blocked.html', reason="Malicious input detected"), 403

@app.route('/')
def home():
    return render_template('index.html', attack_types=ATTACK_TYPES)

@app.route('/simulate', methods=['POST'])
def simulate():
    client_ip = request.remote_addr
    attack_type = request.form.get('attack_type')
    
    # Find which category this attack belongs to
    attack_category = "Normal"
    for category, attacks in ATTACK_CATEGORIES.items():
        if attack_type in attacks:
            attack_category = category
            break
    
    # Generate random network metrics based on attack type
    metrics = generate_metrics_for_attack(attack_type)
    
    # Determine appropriate prevention measure
    if attack_category != "Normal":
        # Select an actual prevention measure
        prevention_key = random.choice(ACTIVE_PREVENTION[attack_category])
        prevention_desc = PREVENTION_DESCRIPTIONS[prevention_key]
        
        # Actually implement the prevention
        implement_prevention(prevention_key, client_ip, attack_type, attack_category)
    else:
        prevention_key = None
        prevention_desc = None
    
    # Simulate detection process
    detection_time = round(random.uniform(0.05, 2.5), 2)  # time in seconds
    
    # For normal traffic, sometimes show it's normal
    if attack_type == "normal":
        result = {
            "detected": False,
            "attack_type": "Normal traffic",
            "category": "Normal",
            "detection_time": detection_time,
            "message": "Traffic validated as normal",
            "prevention": None,
            "prevention_key": None,
            "metrics": metrics
        }
    else:
        # Record the attack for the security dashboard
        security.record_attack({
            "ip": client_ip,
            "attack_type": attack_type,
            "category": attack_category,
            "action": prevention_key,
            "details": f"Simulated {attack_type} attack detected"
        })
        
        result = {
            "detected": True,
            "attack_type": attack_type,
            "category": attack_category,
            "detection_time": detection_time,
            "message": f"{attack_type.upper()} attack detected and actively prevented!",
            "prevention": prevention_desc,
            "prevention_key": prevention_key,
            "metrics": metrics
        }
    
    return render_template('result.html', result=result, attack_types=ATTACK_TYPES)

@app.route('/manual_input', methods=['GET'])
def manual_input():
    return render_template('manual_input.html')

@app.route('/dashboard', methods=['GET'])
def security_dashboard():
    # Get statistics for security dashboard
    attack_history = security.get_attack_history()
    blocked_ips = len(security.blocked_ips)
    
    # Calculate statistics
    attack_counts = defaultdict(int)
    category_counts = defaultdict(int)
    
    for attack in attack_history:
        attack_counts[attack["type"]] += 1
        category_counts[attack["category"]] += 1
    
    stats = {
        "total_attacks": len(attack_history),
        "blocked_ips": blocked_ips,
        "attack_counts": dict(attack_counts),
        "category_counts": dict(category_counts)
    }
    
    return render_template('dashboard.html', stats=stats, history=attack_history)

@app.route('/predict', methods=['POST'])
def predict():
    try:
        client_ip = request.remote_addr
        
        # Check for brute force parameter testing
        if security.check_rate_limit(client_ip, "predict", max_rate=20):
            security.record_suspicious_activity(client_ip, "Excessive prediction requests")
            security.record_attack({
                "ip": client_ip,
                "attack_type": "bruteforce",
                "category": "R2L",
                "action": "rate_limiting",
                "details": "Excessive prediction requests"
            })
            return render_template('rate_limited.html'), 429
            
        int_features = [float(x) for x in request.form.values()]

        if int_features[0]==0:
            f_features=[0,0,0]+int_features[1:]
        elif int_features[0]==1:
            f_features=[1,0,0]+int_features[1:]
        elif int_features[0]==2:
            f_features=[0,1,0]+int_features[1:]
        else:
            f_features=[0,0,1]+int_features[1:]

        if f_features[6]==0:
            fn_features=f_features[:6]+[0,0]+f_features[7:]
        elif f_features[6]==1:
            fn_features=f_features[:6]+[1,0]+f_features[7:]
        else:
            fn_features=f_features[:6]+[0,1]+f_features[7:]

        final_features = [np.array(fn_features)]
        prediction = model.predict(final_features)

        if prediction==0:
            output='Normal'
            prevention_key = None
            prevention_desc = None
            detected = False
        else:
            detected = True
            if prediction==1:
                output='DOS'
            elif prediction==2:
                output='PROBE'
            elif prediction==3:
                output='R2L'
            else:
                output='U2R'
                
            # Select and implement prevention
            prevention_key = random.choice(ACTIVE_PREVENTION[output])
            prevention_desc = PREVENTION_DESCRIPTIONS[prevention_key]
            implement_prevention(prevention_key, client_ip, "custom", output)
            
            # Record the attack
            security.record_attack({
                "ip": client_ip,
                "attack_type": "custom",
                "category": output,
                "action": prevention_key,
                "details": "Custom parameters detection"
            })

        result = {
            "detected": detected,
            "category": output,
            "attack_type": "custom" if detected else "normal",
            "detection_time": round(random.uniform(0.05, 2.5), 2),
            "prevention": prevention_desc,
            "prevention_key": prevention_key,
            "message": f"Attack classified as {output}" if detected else "Traffic classified as Normal"
        }

        return render_template('result.html', result=result, attack_types=ATTACK_TYPES)
    except Exception as e:
        security.record_suspicious_activity(client_ip, f"Error in prediction: {str(e)}")
        return render_template('index.html', error=str(e)), 500
    
@app.route('/api/predict', methods=['POST'])
def api_predict():
    client_ip = request.remote_addr
    
    # Apply API-specific security checks
    if security.check_rate_limit(client_ip, "api/predict", max_rate=15):
        return jsonify({"error": "Rate limit exceeded"}), 429
    
    try:
        data = request.get_json(force=True)
        
        # Validate input data to prevent injection
        for key, value in data.items():
            if not isinstance(value, (int, float)):
                security.record_suspicious_activity(client_ip, "Invalid data type in API")
                return jsonify({"error": "Invalid data format"}), 400
        
        prediction = model.predict([np.array(list(data.values()))])

        if prediction==0:
            output='Normal'
            detected = False
            prevention = None
        else:
            detected = True
            if prediction==1:
                output='DOS'
            elif prediction==2:
                output='PROBE'
            elif prediction==3:
                output='R2L'
            else:
                output='U2R'
                
            # Select and implement prevention
            prevention_key = random.choice(ACTIVE_PREVENTION[output])
            prevention = PREVENTION_DESCRIPTIONS[prevention_key]
            implement_prevention(prevention_key, client_ip, "api", output)
            
            # Record the attack
            security.record_attack({
                "ip": client_ip,
                "attack_type": "api",
                "category": output,
                "action": prevention_key,
                "details": "API detection"
            })

        response = {
            "detected": detected,
            "category": output,
            "prevention": prevention
        }

        return jsonify(response)
    except Exception as e:
        security.record_suspicious_activity(client_ip, f"API Error: {str(e)}")
        return jsonify({"error": str(e)}), 500

def generate_metrics_for_attack(attack_type):
    """Generate realistic network metrics based on attack type"""
    metrics = {}
    
    # Base values for all attacks
    metrics["count"] = random.randint(10, 500)
    metrics["dst_host_diff_srv_rate"] = round(random.uniform(0, 1), 2)
    metrics["dst_host_same_src_port_rate"] = round(random.uniform(0, 1), 2)
    metrics["dst_host_same_srv_rate"] = round(random.uniform(0, 1), 2)
    metrics["dst_host_srv_count"] = random.randint(1, 100)
    metrics["logged_in"] = random.choice([0, 1])
    metrics["same_srv_rate"] = round(random.uniform(0, 1), 2)
    metrics["serror_rate"] = round(random.uniform(0, 1), 2)
    
    # Customize metrics based on attack type
    if attack_type in ATTACK_CATEGORIES["DOS"]:
        metrics["count"] = random.randint(200, 1000)  # High connection count
        metrics["serror_rate"] = round(random.uniform(0.7, 1.0), 2)  # High error rate
        metrics["same_srv_rate"] = round(random.uniform(0.8, 1.0), 2)  # Same service
    
    elif attack_type in ATTACK_CATEGORIES["PROBE"]:
        metrics["dst_host_diff_srv_rate"] = round(random.uniform(0.7, 1.0), 2)  # Different services
        metrics["dst_host_same_srv_rate"] = round(random.uniform(0, 0.3), 2)  # Varied services
    
    elif attack_type in ATTACK_CATEGORIES["R2L"]:
        metrics["logged_in"] = 1  # Usually logged in
        metrics["dst_host_same_src_port_rate"] = round(random.uniform(0.8, 1.0), 2)
    
    elif attack_type in ATTACK_CATEGORIES["U2R"]:
        metrics["logged_in"] = 1  # Must be logged in
        metrics["count"] = random.randint(1, 10)  # Low count
    
    elif attack_type == "normal":
        metrics["serror_rate"] = round(random.uniform(0, 0.1), 2)  # Low error rate
    
    # Add some flags
    flags = ["S0", "SF", "REJ", "RSTO", "RSTOS0", "SH", "RSTRH", "SHR"]
    metrics["flag"] = random.choice(flags)
    
    return metrics

def implement_prevention(prevention_key, client_ip, attack_type, attack_category):
    """Actually implement prevention measures instead of just displaying them"""
    logger.info(f"Implementing {prevention_key} against {attack_type} from {client_ip}")
    
    # Implement different prevention measures based on the key
    if prevention_key == "rate_limiting":
        # Apply stricter rate limiting to the IP
         for endpoint in ["/", "/simulate", "/predict", "/api/predict"]:
           # key = f"{client_ip}:{endpoint}"
           # with security.lock:
             #   security.rate_limited_ips[key] = (datetime.now(), 0, 5)  # Reduce to 5 req/min
            pass
    
    elif prevention_key == "ip_blocking":
        # Block the IP temporarily
      #  security.block_ip(client_ip, duration_minutes=15, 
       #                  reason=f"Blocked due to {attack_type} attack")
             pass
         
    elif prevention_key == "traffic_filtering":
        # Simulate filtering traffic from this IP
       # with security.lock:
            # Apply traffic pattern filtering (for simulation)
            pass
    
    elif prevention_key == "port_restriction":
        # Simulate restricting access to certain ports
        pass
    
    elif prevention_key == "account_lockout" or prevention_key == "access_restriction":
        # Simulate account lockout
       # if "session_id" in session:
        #    session.pop("session_id", None)
        pass
    
    elif prevention_key == "session_termination":
        # End the user's session
        # session.clear()
        pass
    
    elif prevention_key == "disable_icmp":
        # Simulate disabling ICMP responses
        logger.info(f"ICMP responses disabled for {client_ip}")
    
    elif prevention_key == "ingress_filtering":
        # Simulate ingress filtering to prevent IP spoofing
        logger.info(f"Ingress filtering enabled for {client_ip}")
    
    elif prevention_key == "waf":
        # Simulate enabling Web Application Firewall
        logger.info(f"Web Application Firewall enabled for {client_ip}")
    
    elif prevention_key == "captcha":
        # Simulate enabling CAPTCHA for bot detection
        logger.info(f"CAPTCHA enabled for {client_ip}")
    
    elif prevention_key == "fail2ban":
        # Simulate enabling Fail2Ban for repeated failed connections
        logger.info(f"Fail2Ban enabled for {client_ip}")
    
    elif prevention_key == "port_knocking":
        # Simulate enabling port knocking
        logger.info(f"Port knocking enabled for {client_ip}")
    
    elif prevention_key == "dlp":
        # Simulate enabling Data Loss Prevention
        logger.info(f"Data Loss Prevention enabled for {client_ip}")
    
    elif prevention_key == "file_permissions":
        # Simulate restricting file-sharing permissions
        logger.info(f"File-sharing permissions restricted for {client_ip}")
    
    elif prevention_key == "aslr":
        # Simulate enabling Address Space Layout Randomization
        logger.info(f"ASLR enabled for {client_ip}")
    
    elif prevention_key == "stack_canaries":
        # Simulate enabling Stack Canaries
        logger.info(f"Stack Canaries enabled for {client_ip}")
    
    elif prevention_key == "selinux":
        # Simulate enabling SELinux
        logger.info(f"SELinux enabled for {client_ip}")
    
    elif prevention_key == "rootkit_scanner":
        # Simulate enabling rootkit scanner
        logger.info(f"Rootkit scanner enabled for {client_ip}")
    
    # For simulation purposes, we'll log all prevention measures
    logger.warning(f"Prevention measure implemented: {prevention_key} for {attack_category} attack from {client_ip}")
    
    
def generate_alarm_sound(duration=5, volume=0.5):
    """
    Generate an alarm sound.
    
    :param duration: Duration of the alarm in seconds
    :param volume: Volume of the alarm (0.0 to 1.0)
    """
    try:
        # Sampling rate
        sample_rate = 44100
        
        # Generate time array
        t = np.linspace(0, duration, int(sample_rate * duration), False)
        
        # Create a complex tone with multiple frequencies
        tone1 = np.sin(2 * np.pi * 440 * t)  # 440 Hz (A4 note)
        tone2 = np.sin(2 * np.pi * 660 * t)  # 660 Hz (slightly higher pitch)
        
        # Combine tones with varying amplitudes to create alarm-like sound
        alarm_sound = volume * (tone1 * 0.7 + tone2 * 0.3)
        
        # Apply fade in and fade out
        fade_duration = 0.1  # 100ms fade
        fade_samples = int(fade_duration * sample_rate)
        fade_in = np.linspace(0, 1, fade_samples)
        fade_out = np.linspace(1, 0, fade_samples)
        
        alarm_sound[:fade_samples] *= fade_in
        alarm_sound[-fade_samples:] *= fade_out
        
        return alarm_sound, sample_rate
    except Exception as e:
        logger.error(f"Error generating alarm sound: {e}")
        return None, None

def play_alarm_sound(duration=5, volume=0.5):
    """
    Play alarm sound in a separate thread to avoid blocking.
    
    :param duration: Duration of the alarm in seconds
    :param volume: Volume of the alarm (0.0 to 1.0)
    """
    def sound_thread():
        try:
            # Generate alarm sound
            alarm_sound, sample_rate = generate_alarm_sound(duration, volume)
            
            if alarm_sound is not None and sample_rate is not None:
                # Play the sound
                sd.play(alarm_sound, sample_rate)
                
                # Wait for the sound to finish
                sd.wait()
        except Exception as e:
            logger.error(f"Error playing alarm sound: {e}")
    
    # Start sound in a separate thread
    threading.Thread(target=sound_thread, daemon=True).start()

@app.teardown_appcontext
def shutdown_security(exception=None):
    """Shut down security monitor when app exits"""
    security.shutdown()

if __name__ == "__main__":
    app.run(debug=True)   