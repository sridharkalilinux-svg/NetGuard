import re
from collections import defaultdict

class ThreatDetector:
    def __init__(self):
        self.threats = []

    def detect_all(self, analysis_result):
        self.threats = []
        sessions = analysis_result.get('sessions', [])
        
        # Helper structures
        src_ip_dst_ports = defaultdict(set)
        src_ip_dst_ips = defaultdict(set)
        auth_failures = defaultdict(int)
        
        # 1. Iterate sessions for single-pass checks
        for session in sessions:
            src = session['src_ip']
            dst = session['dst_ip']
            sport = session['src_port']
            dport = session['dst_port']
            proto = session['protocol']
            payloads = session['payloads']
            
            # Aggregate for Scanning Detection
            src_ip_dst_ports[src].add(dport)
            src_ip_dst_ips[src].add(dst)

            # 2. SQL Injection & Server-Side Injection
            self.check_payload_injections(session)

            # 3. Clear-Text Credentials
            self.check_clear_text_creds(session)
            
            # 4. Brute Force Heuristics (Basic)
            # SSH/FTP short sessions or high count
            if dport in [21, 22] or proto == 'SSH' or proto == 'FTP':
                # Heuristic: many short sessions might indicate brute force
                if session['packet_count'] < 20 and session['duration'] < 5:
                    auth_failures[(src, dst, dport)] += 1

        # 5. Analyze Aggregates for Scans
        self.detect_port_scans(src_ip_dst_ports)
        self.detect_brute_force(auth_failures)

        return self.threats

    def check_payload_injections(self, session):
        # SQLi Patterns
        sqli_patterns = [
            r"UNION\s+SELECT", r"OR\s+1=1", r"'\s*OR\s*'1'='1", 
            r"--", r"/\*.*\*/", r"xp_cmdshell"
        ]
        # Command Injection / XSS / Path Traversal
        cmd_patterns = [
            r";\s*(ls|cat|pwd|whoami)", r"\|\s*(ls|cat|pwd|whoami)", 
            r"\.\./\.\./", r"/etc/passwd", r"{{.*}}", r"\$\{.*\}"
        ]

        for payload in session['payloads']:
            # Decode if not already (parser usually decodes)
            if not isinstance(payload, str): continue
            
            # Check SQLi
            for pattern in sqli_patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    self.threats.append({
                        'type': 'SQL Injection',
                        'src_ip': session['src_ip'],
                        'dst_ip': session['dst_ip'],
                        'severity': 'High',
                        'detail': f"Pattern found: {pattern}",
                        'timestamp': session['start_time']
                    })
                    break # One per session is enough
            
            # Check Command Injection
            for pattern in cmd_patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    self.threats.append({
                        'type': 'Server-Side Injection',
                        'src_ip': session['src_ip'],
                        'dst_ip': session['dst_ip'],
                        'severity': 'Critical',
                        'detail': f"Pattern found: {pattern}",
                        'timestamp': session['start_time']
                    })
                    break

    def check_clear_text_creds(self, session):
        # Basic patterns for FTP, HTTP Basic Auth, Telnet (if any)
        cred_patterns = [
            r"Authorization:\s*Basic\s+([a-zA-Z0-9+/=]+)", # HTTP Basic
            r"USER\s+(.+)", # FTP
            r"PASS\s+(.+)", # FTP
        ]
        
        for payload in session['payloads']:
            if not isinstance(payload, str): continue
            
            for pattern in cred_patterns:
                match = re.search(pattern, payload, re.IGNORECASE)
                if match:
                    captured = match.group(1)
                    # Don't log the actual pass in a real prod system without care, 
                    # but the requirement says "Detected usernames & passwords"
                    self.threats.append({
                        'type': 'Clear-Text Credentials',
                        'src_ip': session['src_ip'],
                        'dst_ip': session['dst_ip'],
                        'severity': 'High',
                        'detail': f"Credential exposed in {session['protocol']}: {captured[:20]}...",
                        'timestamp': session['start_time']
                    })

    def detect_port_scans(self, src_ip_dst_ports):
        # Thresholds
        PORT_SCAN_THRESHOLD = 10 # distinct ports
        
        for src, ports in src_ip_dst_ports.items():
            if len(ports) > PORT_SCAN_THRESHOLD:
                self.threats.append({
                    'type': 'Reconnaissance (Port Scan)',
                    'src_ip': src,
                    'dst_ip': 'Multiple',
                    'severity': 'Medium',
                    'detail': f"Scanned {len(ports)} distinct ports",
                    'timestamp': None # Aggregate
                })

    def detect_brute_force(self, auth_failures):
        THRESHOLD = 5
        for (src, dst, port), count in auth_failures.items():
            if count > THRESHOLD:
                self.threats.append({
                    'type': 'Brute Force Attempt',
                    'src_ip': src,
                    'dst_ip': dst,
                    'severity': 'High',
                    'detail': f"{count} failed/short sessions on port {port}",
                    'timestamp': None
                })
