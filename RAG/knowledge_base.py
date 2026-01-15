# Knowledge Base: MITRE ATT&CK Threat Intelligence

THREAT_KNOWLEDGE_BASE = {
    "application": [
        {
            "threat_id": "APP_001",
            "name": "SQL Injection (SQLi)",
            "category": "Injection Attacks",
            "description": "SQL Injection is a code injection technique where an attacker inserts malicious SQL statements into input fields. The attacker can manipulate database queries to extract, modify, or delete data. Common vectors include login forms, search boxes, and URL parameters.",
            "indicators": ["SQL keywords in input", "Unusual query patterns", "Database error messages", "Unexpected data access"],
            "mitre_id": "T1190",
            "impact": "Data breach, unauthorized access, data manipulation",
            "remediation": "Use parameterized queries, input validation, WAF rules, principle of least privilege"
        },
        {
            "threat_id": "APP_002",
            "name": "Cross-Site Scripting (XSS)",
            "category": "Injection Attacks",
            "description": "XSS attacks inject malicious scripts into web pages viewed by other users. Stored XSS persists in databases, Reflected XSS is immediate, DOM-based XSS manipulates client-side code. Attackers can steal cookies, sessions, or perform actions on behalf of users.",
            "indicators": ["Script tags in input", "JavaScript event handlers", "HTML encoding issues", "Session hijacking attempts"],
            "mitre_id": "T1190",
            "impact": "Session hijacking, credential theft, malware distribution",
            "remediation": "Input sanitization, output encoding, CSP headers, HTTPOnly cookies"
        },
        {
            "threat_id": "APP_003",
            "name": "Broken Authentication",
            "category": "Broken Auth",
            "description": "Weak authentication mechanisms allow attackers to compromise user accounts. This includes weak passwords, session fixation, credential stuffing, and lack of MFA. Attackers can gain unauthorized access to user accounts and sensitive data.",
            "indicators": ["Multiple failed login attempts", "Unusual login locations", "Session reuse", "Weak password patterns"],
            "mitre_id": "T1110",
            "impact": "Unauthorized account access, data theft, privilege escalation",
            "remediation": "Implement MFA, strong password policies, session management, account lockout mechanisms"
        },
        {
            "threat_id": "APP_004",
            "name": "Business Logic Abuse",
            "category": "Business Logic Abuse",
            "description": "Attackers exploit flaws in application business logic to bypass security controls. This includes price manipulation, inventory bypass, workflow manipulation, and authorization flaws. Legitimate-looking requests are used to perform unauthorized actions.",
            "indicators": ["Unusual transaction patterns", "Negative inventory", "Price discrepancies", "Workflow bypass"],
            "mitre_id": "T1021",
            "impact": "Financial loss, data manipulation, unauthorized actions",
            "remediation": "Thorough security testing, input validation, transaction logging, rate limiting"
        },
        {
            "threat_id": "APP_005",
            "name": "Insecure Deserialization",
            "category": "Dependency Vulns",
            "description": "Deserialization of untrusted data can lead to remote code execution. Attackers craft malicious serialized objects that execute arbitrary code when deserialized. Common in Java, Python, and PHP applications.",
            "indicators": ["Serialized object inputs", "Unexpected code execution", "Process spawning", "File system access"],
            "mitre_id": "T1203",
            "impact": "Remote code execution, system compromise",
            "remediation": "Avoid deserializing untrusted data, use safe serialization formats, implement integrity checks"
        },
        {
            "threat_id": "APP_006",
            "name": "Dependency Vulnerabilities",
            "category": "Dependency Vulns",
            "description": "Vulnerable third-party libraries and dependencies can be exploited to compromise applications. Attackers use known CVEs in outdated packages to gain code execution or access sensitive data.",
            "indicators": ["Outdated package versions", "Known CVE exploitation", "Unexpected behavior from libraries"],
            "mitre_id": "T1195",
            "impact": "Code execution, data theft, system compromise",
            "remediation": "Regular dependency updates, vulnerability scanning, SCA tools, version pinning"
        },
        {
            "threat_id": "APP_007",
            "name": "Data Leaks",
            "category": "Data Leaks",
            "description": "Sensitive data is exposed through various vectors: unencrypted transmission, insecure storage, verbose error messages, or unauthorized access. PII, credentials, and business data are compromised.",
            "indicators": ["Unencrypted data transmission", "Sensitive data in logs", "Exposed API responses", "Backup file exposure"],
            "mitre_id": "T1041",
            "impact": "Privacy violation, compliance breach, identity theft",
            "remediation": "Encryption in transit/at rest, data masking, secure logging, access controls"
        }
    ],
    "container": [
        {
            "threat_id": "CONT_001",
            "name": "Container Escape",
            "category": "Container Escape",
            "description": "Attackers exploit kernel vulnerabilities or container runtime flaws to break out of container isolation and access the host system. This provides full system compromise and lateral movement capabilities.",
            "indicators": ["Kernel exploit attempts", "Unusual system calls", "Host filesystem access", "Process spawning outside container"],
            "mitre_id": "T1611",
            "impact": "Host compromise, lateral movement, data theft",
            "remediation": "Keep kernel updated, use seccomp/AppArmor, minimal container images, runtime security monitoring"
        },
        {
            "threat_id": "CONT_002",
            "name": "Privilege Escalation",
            "category": "Privilege Escalation",
            "description": "Attackers escalate from low-privilege container processes to root/admin access. This enables full container control and potential host compromise. Methods include SUID binaries, kernel exploits, and misconfigured permissions.",
            "indicators": ["Root process execution", "Capability abuse", "SUID binary execution", "Sudo usage"],
            "mitre_id": "T1548",
            "impact": "Full container control, host compromise",
            "remediation": "Run as non-root, drop unnecessary capabilities, remove SUID binaries, use read-only filesystems"
        },
        {
            "threat_id": "CONT_003",
            "name": "Insecure Container Images",
            "category": "Insecure Images",
            "description": "Vulnerable or malicious container images introduce security risks. This includes outdated base images with CVEs, hardcoded credentials, malware, or unnecessary packages. Supply chain attacks can inject malicious code.",
            "indicators": ["Outdated base images", "Known CVEs in layers", "Hardcoded secrets", "Suspicious packages"],
            "mitre_id": "T1195.03",
            "impact": "Code execution, data theft, supply chain compromise",
            "remediation": "Image scanning, minimal base images, signed images, regular updates, secret management"
        },
        {
            "threat_id": "CONT_004",
            "name": "Secrets Exposure",
            "category": "Secrets Exposure",
            "description": "Sensitive credentials (API keys, passwords, tokens) are exposed in container images, environment variables, or logs. Attackers use these to access external systems and escalate privileges.",
            "indicators": ["Credentials in environment", "Secrets in image layers", "Exposed in logs", "Hardcoded API keys"],
            "mitre_id": "T1552",
            "impact": "Unauthorized access, lateral movement, system compromise",
            "remediation": "Secret management tools, environment-based config, image scanning, log redaction"
        },
        {
            "threat_id": "CONT_005",
            "name": "Supply Chain Attacks",
            "category": "Supply Chain Attacks",
            "description": "Attackers compromise container registries, base images, or dependencies to inject malicious code. This affects all systems using the compromised components. Can be widespread and difficult to detect.",
            "indicators": ["Unexpected image updates", "Unusual network connections", "Cryptomining activity", "Backdoor processes"],
            "mitre_id": "T1195",
            "impact": "Widespread compromise, data theft, cryptomining",
            "remediation": "Image signing/verification, registry security, dependency scanning, runtime monitoring"
        },
        {
            "threat_id": "CONT_006",
            "name": "DoS via Resource Exhaustion",
            "category": "DoS due to no resource limits",
            "description": "Containers without resource limits can consume all available CPU, memory, or disk, causing denial of service. A single compromised container can impact all other containers on the host.",
            "indicators": ["High CPU/memory usage", "Disk space exhaustion", "Service unavailability", "Process multiplication"],
            "mitre_id": "T1499",
            "impact": "Service unavailability, system instability",
            "remediation": "Set CPU/memory limits, disk quotas, monitoring, rate limiting, resource isolation"
        }
    ],
    "network": [
        {
            "threat_id": "NET_001",
            "name": "Man-in-the-Middle (MitM)",
            "category": "MitM",
            "description": "Attackers intercept communication between two parties to eavesdrop or modify data. Methods include ARP spoofing, DNS hijacking, SSL stripping, and rogue access points. Enables credential theft and data manipulation.",
            "indicators": ["Certificate warnings", "Unusual gateway changes", "Traffic redirection", "SSL/TLS downgrade"],
            "mitre_id": "T1557",
            "impact": "Data theft, credential compromise, data manipulation",
            "remediation": "HTTPS/TLS enforcement, certificate pinning, network segmentation, ARP monitoring"
        },
        {
            "threat_id": "NET_002",
            "name": "Unencrypted Traffic",
            "category": "Unencrypted Traffic",
            "description": "Sensitive data transmitted in plaintext is vulnerable to eavesdropping. HTTP, telnet, FTP, and unencrypted protocols expose credentials and data to network sniffing attacks.",
            "indicators": ["HTTP traffic with sensitive data", "Plaintext credentials", "Unencrypted protocols", "No TLS/SSL"],
            "mitre_id": "T1040",
            "impact": "Data theft, credential compromise, privacy violation",
            "remediation": "Enforce HTTPS/TLS, disable legacy protocols, network encryption, VPN usage"
        },
        {
            "threat_id": "NET_003",
            "name": "DNS Spoofing",
            "category": "DNS Spoofing",
            "description": "Attackers redirect DNS queries to malicious IP addresses, causing users to visit fake websites. Methods include DNS cache poisoning, rogue DNS servers, and DHCP spoofing. Used for phishing and credential theft.",
            "indicators": ["DNS query anomalies", "Unexpected IP resolutions", "Certificate mismatches", "Unusual domain access"],
            "mitre_id": "T1557.02",
            "impact": "Phishing, credential theft, malware distribution",
            "remediation": "DNSSEC, DNS filtering, monitoring, secure DNS servers, certificate validation"
        },
        {
            "threat_id": "NET_004",
            "name": "Distributed Denial of Service (DDoS)",
            "category": "DDoS",
            "description": "Attackers overwhelm services with traffic from multiple sources, causing unavailability. Types include volumetric (bandwidth), protocol (resource), and application-layer attacks. Can be amplified through botnets.",
            "indicators": ["Massive traffic spike", "Multiple source IPs", "Service unavailability", "High bandwidth usage"],
            "mitre_id": "T1498",
            "impact": "Service unavailability, business disruption",
            "remediation": "DDoS mitigation services, rate limiting, traffic filtering, redundancy, CDN"
        },
        {
            "threat_id": "NET_005",
            "name": "Lateral Movement",
            "category": "Lateral Movement",
            "description": "After initial compromise, attackers move through the network to access other systems. Methods include credential reuse, network reconnaissance, and exploitation of trust relationships between systems.",
            "indicators": ["Unusual inter-system traffic", "Credential reuse", "Network scanning", "Privilege escalation"],
            "mitre_id": "T1570",
            "impact": "Widespread compromise, data theft, privilege escalation",
            "remediation": "Network segmentation, zero-trust architecture, monitoring, credential management"
        },
        {
            "threat_id": "NET_006",
            "name": "Replay Attacks",
            "category": "Replay Attacks",
            "description": "Attackers capture and replay legitimate network traffic to perform unauthorized actions. Without proper nonce/timestamp validation, repeated authentication or transaction messages can be exploited.",
            "indicators": ["Duplicate requests", "Repeated authentication", "Unusual transaction timing", "Session reuse"],
            "mitre_id": "T1040",
            "impact": "Unauthorized actions, transaction fraud, authentication bypass",
            "remediation": "Nonce/timestamp validation, TLS/SSL, session management, request signing"
        },
        {
            "threat_id": "NET_007",
            "name": "Port Scanning",
            "category": "Port Scanning",
            "description": "Attackers scan networks to identify open ports and running services. This reconnaissance activity reveals potential attack surfaces and vulnerable services. Precursor to exploitation attacks.",
            "indicators": ["Multiple port connection attempts", "Network scanning tools", "Unusual port access patterns", "Service enumeration"],
            "mitre_id": "T1046",
            "impact": "Reconnaissance, vulnerability identification",
            "remediation": "Firewall rules, port filtering, network monitoring, IDS/IPS"
        }
    ]
}

def get_threats_by_layer(layer: str):
    """Get all threats for a specific layer"""
    return THREAT_KNOWLEDGE_BASE.get(layer, [])

def get_threat_by_id(threat_id: str):
    """Get a specific threat by ID"""
    for layer in THREAT_KNOWLEDGE_BASE.values():
        for threat in layer:
            if threat["threat_id"] == threat_id:
                return threat
    return None

def get_all_threats():
    """Get all threats across all layers"""
    all_threats = []
    for layer in THREAT_KNOWLEDGE_BASE.values():
        all_threats.extend(layer)
    return all_threats
