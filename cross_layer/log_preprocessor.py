import re
import json
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib


class LogLayer(Enum):
    """Log source layer"""
    APPLICATION = "application"
    CONTAINER = "container"
    NETWORK = "network"
    ATTACK = "attack"


class EventType(Enum):
    """Standardized event types across layers"""
    AUTH_ATTEMPT = "auth_attempt"
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    PAYMENT_PROCESS = "payment_process"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    REVERSE_SHELL = "reverse_shell"
    PORT_SCAN = "port_scan"
    DOS_ATTACK = "dos_attack"
    BRUTE_FORCE = "brute_force"
    SQL_INJECTION = "sql_injection"
    CONTAINER_EXEC = "container_exec"
    NETWORK_CONNECT = "network_connect"
    NORMAL = "normal"


@dataclass
class LogNode:
    """Represents a single log entry as a graph node"""
    node_id: str  # Hash of log content for uniqueness
    timestamp: float  # Unix epoch
    layer: LogLayer
    event_type: EventType
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    user_id: Optional[str] = None
    email: Optional[str] = None
    service: Optional[str] = None
    container_id: Optional[str] = None
    raw_content: str = ""
    risk_score: float = 0.0
    attributes: Dict = None

    def __post_init__(self):
        if self.attributes is None:
            self.attributes = {}


class ApplicationLogParser:
    """Parse application layer logs (nginx, service logs)"""

    # Timestamp patterns
    TIMESTAMP_PATTERN = r'timestamp="([^"]+)"'
    ISO_TIMESTAMP = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+-]\d{2}:\d{2})'
    
    # Event extraction
    EVENT_PATTERN = r'event="([^"]+)"'
    METHOD_PATTERN = r'Method="([^"]+)"'
    URL_PATTERN = r'URL="([^"]+)"'
    
    # User/Auth patterns
    USER_ID_PATTERN = r'userId="([^"]+)"'
    EMAIL_PATTERN = r'email="([^"]+)"'
    USER_AGENT_PATTERN = r'User-Agent="([^"]+)"'
    
    # Service identification
    SERVICE_PATTERN = r'^([a-z-]+)-\d+\s*\|'
    
    # Content extraction for SQL injection detection
    CONTENT_PATTERN = r'content="({[^}]+})"'
    SQL_INJECTION_PATTERNS = [
        r"(\bOR\b|\bAND\b)\s*\d+\s*=\s*\d+",
        r"(UNION|SELECT|INSERT|UPDATE|DELETE|DROP)\s+",
        r"(--|#|/\*|\*/)",
        r"(\\x27|\\x22|'|\")",
    ]

    @staticmethod
    def parse_timestamp(timestamp_str: str) -> float:
        """Convert ISO 8601 or custom format to Unix epoch"""
        try:
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            return dt.timestamp()
        except:
            try:
                dt = datetime.strptime(timestamp_str, '%Y/%m/%d %H:%M:%S')
                return dt.timestamp()
            except:
                return datetime.now().timestamp()

    @staticmethod
    def extract_event_type(event_str: str) -> EventType:
        """Map event string to EventType enum"""
        event_lower = event_str.lower()
        
        if 'auth' in event_lower and 'attempt' in event_lower:
            return EventType.AUTH_ATTEMPT
        elif 'auth' in event_lower and 'success' in event_lower:
            return EventType.AUTH_SUCCESS
        elif 'auth' in event_lower and 'failure' in event_lower:
            return EventType.AUTH_FAILURE
        elif 'payment' in event_lower:
            return EventType.PAYMENT_PROCESS
        else:
            return EventType.NORMAL

    @staticmethod
    def detect_sql_injection(content: str) -> bool:
        """Detect SQL injection patterns in content"""
        for pattern in ApplicationLogParser.SQL_INJECTION_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False

    @classmethod
    def parse(cls, line: str) -> Optional[LogNode]:
        """Parse a single application log line"""
        if not line.strip():
            return None

        ts_match = re.search(cls.TIMESTAMP_PATTERN, line)
        if not ts_match:
            ts_match = re.search(cls.ISO_TIMESTAMP, line)
        timestamp = cls.parse_timestamp(ts_match.group(1)) if ts_match else datetime.now().timestamp()

        event_match = re.search(cls.EVENT_PATTERN, line)
        event_type = cls.extract_event_type(event_match.group(1)) if event_match else EventType.NORMAL

        user_id_match = re.search(cls.USER_ID_PATTERN, line)
        email_match = re.search(cls.EMAIL_PATTERN, line)
        user_agent_match = re.search(cls.USER_AGENT_PATTERN, line)

        service_match = re.search(cls.SERVICE_PATTERN, line)
        service = service_match.group(1) if service_match else "unknown"

        method_match = re.search(cls.METHOD_PATTERN, line)
        url_match = re.search(cls.URL_PATTERN, line)

        content_match = re.search(cls.CONTENT_PATTERN, line)
        risk_score = 0.0
        if content_match:
            content = content_match.group(1)
            if cls.detect_sql_injection(content):
                event_type = EventType.SQL_INJECTION
                risk_score = 0.9

        node_id = hashlib.md5(line.encode()).hexdigest()
        
        return LogNode(
            node_id=node_id,
            timestamp=timestamp,
            layer=LogLayer.APPLICATION,
            event_type=event_type,
            user_id=user_id_match.group(1) if user_id_match else None,
            email=email_match.group(1) if email_match else None,
            service=service,
            raw_content=line,
            risk_score=risk_score,
            attributes={
                'method': method_match.group(1) if method_match else None,
                'url': url_match.group(1) if url_match else None,
                'user_agent': user_agent_match.group(1) if user_agent_match else None,
            }
        )


class ContainerLogParser:
    """Parse container layer logs (Docker events, audit logs)"""

    # Docker event patterns
    DOCKER_EVENT_PATTERN = r'"(status|Action)":"([^"]+)"'
    CONTAINER_ID_PATTERN = r'"id":"([a-f0-9]{64})"'
    CONTAINER_NAME_PATTERN = r'"name":"([^"]+)"'
    TIME_PATTERN = r'"time":(\d+)'
    
    # Audit log patterns
    AUDIT_TIMESTAMP = r'msg=audit\((\d+\.\d+):(\d+)\)'
    AUDIT_SYSCALL = r'syscall=(\w+)'
    AUDIT_SUCCESS = r'success=(yes|no)'
    AUDIT_UID = r'uid=(\w+)'
    AUDIT_COMM = r'comm=([^\s]+)'
    AUDIT_EXE = r'exe=([^\s]+)'
    
    # Privilege escalation patterns
    PRIV_ESC_PATTERNS = [
        r'(sudo|su|chmod|chown)',
        r'(cap_sys_admin|cap_dac_override)',
    ]
    
    # Reverse shell patterns
    REVERSE_SHELL_PATTERNS = [
        r'/bin/sh.*nc\s+',
        r'bash.*-i.*nc',
        r'(wget|curl).*payload',
        r'mknod.*fifo',
    ]

    @staticmethod
    def extract_event_type(action: str) -> EventType:
        """Map Docker action to EventType"""
        action_lower = action.lower()
        
        if 'exec' in action_lower:
            return EventType.CONTAINER_EXEC
        else:
            return EventType.NORMAL

    @staticmethod
    def detect_privilege_escalation(content: str) -> bool:
        """Detect privilege escalation attempts"""
        for pattern in ContainerLogParser.PRIV_ESC_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False

    @staticmethod
    def detect_reverse_shell(content: str) -> bool:
        """Detect reverse shell commands"""
        for pattern in ContainerLogParser.REVERSE_SHELL_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False

    @classmethod
    def parse_docker_event(cls, line: str) -> Optional[LogNode]:
        """Parse Docker event JSON"""
        try:
            event = json.loads(line)
        except:
            return None

        action = event.get('Action', event.get('status', 'unknown'))
        event_type = cls.extract_event_type(action)
        timestamp = event.get('time', datetime.now().timestamp())
        container_id = event.get('id', '')[:12]
        container_name = event.get('from', 'unknown')
        
        risk_score = 0.0
        if cls.detect_privilege_escalation(action):
            event_type = EventType.PRIVILEGE_ESCALATION
            risk_score = 0.8
        elif cls.detect_reverse_shell(action):
            event_type = EventType.REVERSE_SHELL
            risk_score = 0.95

        node_id = hashlib.md5(line.encode()).hexdigest()
        
        return LogNode(
            node_id=node_id,
            timestamp=float(timestamp),
            layer=LogLayer.CONTAINER,
            event_type=event_type,
            container_id=container_id,
            service=container_name,
            raw_content=line,
            risk_score=risk_score,
            attributes=event
        )

    @classmethod
    def parse_audit_log(cls, line: str) -> Optional[LogNode]:
        """Parse Linux audit log"""
        if 'audit' not in line:
            return None

        ts_match = re.search(cls.AUDIT_TIMESTAMP, line)
        timestamp = float(ts_match.group(1)) if ts_match else datetime.now().timestamp()

        syscall_match = re.search(cls.AUDIT_SYSCALL, line)
        syscall = syscall_match.group(1) if syscall_match else 'unknown'

        success_match = re.search(cls.AUDIT_SUCCESS, line)
        success = success_match.group(1) == 'yes' if success_match else False

        uid_match = re.search(cls.AUDIT_UID, line)
        comm_match = re.search(cls.AUDIT_COMM, line)
        exe_match = re.search(cls.AUDIT_EXE, line)

        event_type = EventType.NORMAL
        risk_score = 0.0
        
        if cls.detect_privilege_escalation(line):
            event_type = EventType.PRIVILEGE_ESCALATION
            risk_score = 0.7

        node_id = hashlib.md5(line.encode()).hexdigest()
        
        return LogNode(
            node_id=node_id,
            timestamp=timestamp,
            layer=LogLayer.CONTAINER,
            event_type=event_type,
            raw_content=line,
            risk_score=risk_score,
            attributes={
                'syscall': syscall,
                'success': success,
                'uid': uid_match.group(1) if uid_match else None,
                'comm': comm_match.group(1) if comm_match else None,
                'exe': exe_match.group(1) if exe_match else None,
            }
        )


class NetworkLogParser:
    """Parse network layer logs (tcpdump, flow data)"""

    TCPDUMP_PATTERN = r'(\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+([\d.]+)\.([\d]+)\s*>\s*([\d.]+)\.([\d]+)'
    TCPDUMP_FLAGS = r'Flags\s*\[([^\]]+)\]'
    TCPDUMP_HTTP = r'HTTP: (GET|POST|PUT|DELETE|HEAD)\s+([^\s]+)'

    @staticmethod
    def parse_timestamp(ts_str: str) -> float:
        """Parse tcpdump timestamp"""
        try:
            now = datetime.now()
            time_obj = datetime.strptime(ts_str, '%H:%M:%S.%f')
            dt = now.replace(hour=time_obj.hour, minute=time_obj.minute, 
                            second=time_obj.second, microsecond=time_obj.microsecond)
            return dt.timestamp()
        except:
            return datetime.now().timestamp()

    @staticmethod
    def classify_network_event(src_ip: str, dst_ip: str, dst_port: int, 
                              flags: str, http_method: Optional[str]) -> EventType:
        """Classify network event based on characteristics"""
        if dst_port in [22, 23, 3389]:
            if 'S' in flags and 'A' not in flags:
                return EventType.PORT_SCAN
        if http_method:
            return EventType.NORMAL
        return EventType.NETWORK_CONNECT

    @classmethod
    def parse_tcpdump(cls, line: str) -> Optional[LogNode]:
        """Parse tcpdump output line"""
        match = re.search(cls.TCPDUMP_PATTERN, line)
        if not match:
            return None

        timestamp_str, src_ip, src_port, dst_ip, dst_port = match.groups()
        timestamp = cls.parse_timestamp(timestamp_str)
        src_port = int(src_port)
        dst_port = int(dst_port)

        flags_match = re.search(cls.TCPDUMP_FLAGS, line)
        flags = flags_match.group(1) if flags_match else ''

        http_match = re.search(cls.TCPDUMP_HTTP, line)
        http_method = http_match.group(1) if http_match else None

        event_type = cls.classify_network_event(src_ip, dst_ip, dst_port, flags, http_method)
        risk_score = 0.0
        if event_type == EventType.PORT_SCAN:
            risk_score = 0.6

        node_id = hashlib.md5(line.encode()).hexdigest()
        
        return LogNode(
            node_id=node_id,
            timestamp=timestamp,
            layer=LogLayer.NETWORK,
            event_type=event_type,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            raw_content=line,
            risk_score=risk_score,
            attributes={
                'flags': flags,
                'http_method': http_method,
            }
        )

    @classmethod
    def parse_csv_flow(cls, row: Dict, attack_type: str = 'normal') -> Optional[LogNode]:
        """Parse network flow from CSV (attack datasets)"""
        try:
            src_ip = row.get('src_ip')
            dst_ip = row.get('dst_ip')
            src_port = int(row.get('src_port', 0))
            dst_port = int(row.get('dst_port', 0))
            timestamp_str = row.get('timestamp', '')
            
            dt = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            timestamp = dt.timestamp()
            
            event_type = EventType.NORMAL
            risk_score = 0.0
            
            if attack_type.lower() == 'brute_force':
                event_type = EventType.BRUTE_FORCE
                risk_score = 0.8
            elif attack_type.lower() == 'dos':
                event_type = EventType.DOS_ATTACK
                risk_score = 0.85
            elif attack_type.lower() == 'portscan':
                event_type = EventType.PORT_SCAN
                risk_score = 0.6
            
            node_id = hashlib.md5(f"{src_ip}{dst_ip}{src_port}{dst_port}{timestamp}".encode()).hexdigest()
            
            return LogNode(
                node_id=node_id,
                timestamp=timestamp,
                layer=LogLayer.ATTACK,
                event_type=event_type,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                raw_content=json.dumps(row),
                risk_score=risk_score,
                attributes=row
            )
        except Exception as e:
            print(f"Error parsing CSV flow: {e}")
            return None


class LogPreprocessor:
    """Main preprocessor orchestrating all parsers"""

    def __init__(self):
        self.nodes: List[LogNode] = []
        self.edges: List[Tuple[str, str, Dict]] = []

    def parse_application_logs(self, filepath: str) -> List[LogNode]:
        """Parse application log file"""
        nodes = []
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                node = ApplicationLogParser.parse(line)
                if node:
                    nodes.append(node)
        return nodes

    def parse_container_logs(self, filepath: str) -> List[LogNode]:
        """Parse container log file (mixed format)"""
        nodes = []
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if line.strip().startswith('{'):
                    node = ContainerLogParser.parse_docker_event(line)
                else:
                    node = ContainerLogParser.parse_audit_log(line)
                if node:
                    nodes.append(node)
        return nodes

    def parse_network_logs(self, filepath: str) -> List[LogNode]:
        """Parse network log file (tcpdump format)"""
        nodes = []
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                node = NetworkLogParser.parse_tcpdump(line)
                if node:
                    nodes.append(node)
        return nodes

    def parse_attack_csv(self, filepath: str, attack_type: str) -> List[LogNode]:
        """Parse attack CSV file"""
        import csv
        nodes = []
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                node = NetworkLogParser.parse_csv_flow(row, attack_type)
                if node:
                    nodes.append(node)
        return nodes

    def create_temporal_edges(self, nodes: List[LogNode], time_window: float = 5.0) -> List[Tuple[str, str, Dict]]:
        """Create edges based on temporal proximity and IP correlation"""
        edges = []
        sorted_nodes = sorted(nodes, key=lambda x: x.timestamp)
        
        for i, node1 in enumerate(sorted_nodes):
            for node2 in sorted_nodes[i+1:]:
                if node2.timestamp - node1.timestamp > time_window:
                    break
                
                ip_match = False
                if node1.src_ip and node2.src_ip and node1.src_ip == node2.src_ip:
                    ip_match = True
                if node1.dst_ip and node2.dst_ip and node1.dst_ip == node2.dst_ip:
                    ip_match = True
                if node1.src_ip and node2.dst_ip and node1.src_ip == node2.dst_ip:
                    ip_match = True
                
                user_match = False
                if node1.user_id and node2.user_id and node1.user_id == node2.user_id:
                    user_match = True
                if node1.email and node2.email and node1.email == node2.email:
                    user_match = True
                
                if ip_match or user_match:
                    edge_attrs = {
                        'time_delta': node2.timestamp - node1.timestamp,
                        'type': 'temporal',
                        'correlation': 'ip' if ip_match else 'user',
                    }
                    edges.append((node1.node_id, node2.node_id, edge_attrs))
        
        return edges

    def create_cross_layer_edges(self, nodes: List[LogNode]) -> List[Tuple[str, str, Dict]]:
        """Create edges connecting events across layers"""
        edges = []
        
        for i, node1 in enumerate(nodes):
            for node2 in nodes[i+1:]:
                if node1.layer == node2.layer:
                    continue
                
                if node1.src_ip and node2.src_ip and node1.src_ip == node2.src_ip:
                    edge_attrs = {
                        'type': 'cross_layer',
                        'correlation': 'src_ip',
                        'layers': f"{node1.layer.value}-{node2.layer.value}",
                    }
                    edges.append((node1.node_id, node2.node_id, edge_attrs))
                
                if node1.user_id and node2.user_id and node1.user_id == node2.user_id:
                    edge_attrs = {
                        'type': 'cross_layer',
                        'correlation': 'user_id',
                        'layers': f"{node1.layer.value}-{node2.layer.value}",
                    }
                    edges.append((node1.node_id, node2.node_id, edge_attrs))
        
        return edges

    def export_to_graph_format(self, output_dir: str = './graph_data'):
        """Export nodes and edges to graph format (JSON)"""
        import os
        os.makedirs(output_dir, exist_ok=True)
        
        nodes_data = []
        for node in self.nodes:
            node_dict = asdict(node)
            node_dict['layer'] = node.layer.value
            node_dict['event_type'] = node.event_type.value
            nodes_data.append(node_dict)
        
        with open(f'{output_dir}/nodes.jsonl', 'w') as f:
            for node in nodes_data:
                f.write(json.dumps(node) + '\n')
        
        edges_data = []
        for src_id, dst_id, attrs in self.edges:
            edges_data.append({
                'source': src_id,
                'target': dst_id,
                'attributes': attrs
            })
        
        with open(f'{output_dir}/edges.jsonl', 'w') as f:
            for edge in edges_data:
                f.write(json.dumps(edge) + '\n')
        
        print(f"Exported {len(self.nodes)} nodes and {len(self.edges)} edges to {output_dir}")


    def parse_docker_events_jsonl(self, filepath: str, attack_type: str = 'benign') -> List[LogNode]:
        """Parse Docker events from JSONL file (benign_events.jsonl, priv_esc_events.jsonl, reverse_shell_events.jsonl)"""
        nodes = []
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                node = ContainerLogParser.parse_docker_event(line)
                if node:
                    # Override event type based on attack type
                    if attack_type == 'priv_esc':
                        node.event_type = EventType.PRIVILEGE_ESCALATION
                        node.risk_score = 0.8
                    elif attack_type == 'reverse_shell':
                        node.event_type = EventType.REVERSE_SHELL
                        node.risk_score = 0.95
                    nodes.append(node)
        return nodes

    def parse_sqli_logs(self, filepath: str) -> List[LogNode]:
        """Parse structured SQL injection logs (structured_sqli.log)"""
        nodes = []
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                node = ApplicationLogParser.parse(line)
                if node:
                    nodes.append(node)
        return nodes


if __name__ == "__main__":
    preprocessor = LogPreprocessor()
    
    print("="*70)
    print("PREPROCESSING ALL LOGS")
    print("="*70)
    
    # BENIGN LOGS
    print("\n[BENIGN DATA]")
    print("Parsing application logs...")
    app_nodes = preprocessor.parse_application_logs('application_logs_benign.txt')
    preprocessor.nodes.extend(app_nodes)
    print(f"  ✓ Found {len(app_nodes)} application events")
    
    print("Parsing container logs...")
    container_nodes = preprocessor.parse_container_logs('container_logs_benign.txt')
    preprocessor.nodes.extend(container_nodes)
    print(f"  ✓ Found {len(container_nodes)} container events")
    
    print("Parsing network logs...")
    network_nodes = preprocessor.parse_network_logs('network_logs_benign.txt')
    preprocessor.nodes.extend(network_nodes)
    print(f"  ✓ Found {len(network_nodes)} network events")
    
    print("Parsing benign Docker events...")
    benign_docker = preprocessor.parse_docker_events_jsonl('benign_events.jsonl', 'benign')
    preprocessor.nodes.extend(benign_docker)
    print(f"  ✓ Found {len(benign_docker)} benign Docker events")
    
    # ATTACK LOGS
    print("\n[ATTACK DATA]")
    print("Parsing privilege escalation events...")
    priv_esc = preprocessor.parse_docker_events_jsonl('priv_esc_events.jsonl', 'priv_esc')
    preprocessor.nodes.extend(priv_esc)
    print(f"  ✓ Found {len(priv_esc)} privilege escalation events")
    
    print("Parsing reverse shell events...")
    reverse_shell = preprocessor.parse_docker_events_jsonl('reverse_shell_events.jsonl', 'reverse_shell')
    preprocessor.nodes.extend(reverse_shell)
    print(f"  ✓ Found {len(reverse_shell)} reverse shell events")
    
    print("Parsing SQL injection logs...")
    sqli_logs = preprocessor.parse_sqli_logs('structured_sqli.log')
    preprocessor.nodes.extend(sqli_logs)
    print(f"  ✓ Found {len(sqli_logs)} SQL injection logs")
    
    print("Parsing brute force attacks...")
    brute_force = preprocessor.parse_attack_csv('brute_force.csv', 'brute_force')
    preprocessor.nodes.extend(brute_force)
    print(f"  ✓ Found {len(brute_force)} brute force flows")
    
    print("Parsing DoS attacks...")
    dos = preprocessor.parse_attack_csv('dos.csv', 'dos')
    preprocessor.nodes.extend(dos)
    print(f"  ✓ Found {len(dos)} DoS flows")
    
    print("Parsing port scans...")
    portscan = preprocessor.parse_attack_csv('portscan.csv', 'portscan')
    preprocessor.nodes.extend(portscan)
    print(f"  ✓ Found {len(portscan)} port scan flows")
    
    print("\n[EDGE CREATION]")
    print("Creating temporal edges...")
    temporal_edges = preprocessor.create_temporal_edges(preprocessor.nodes, time_window=10.0)
    preprocessor.edges.extend(temporal_edges)
    print(f"  ✓ Created {len(temporal_edges)} temporal edges")
    
    print("Creating cross-layer edges...")
    cross_layer_edges = preprocessor.create_cross_layer_edges(preprocessor.nodes)
    preprocessor.edges.extend(cross_layer_edges)
    print(f"  ✓ Created {len(cross_layer_edges)} cross-layer edges")
    
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print(f"Total Nodes: {len(preprocessor.nodes)}")
    print(f"Total Edges: {len(preprocessor.edges)}")
    print(f"\nBreakdown:")
    print(f"  - Application: {len(app_nodes) + len(sqli_logs)}")
    print(f"  - Container: {len(container_nodes) + len(benign_docker) + len(priv_esc) + len(reverse_shell)}")
    print(f"  - Network: {len(network_nodes) + len(brute_force) + len(dos) + len(portscan)}")
    
    print("\n[EXPORT]")
    print("Exporting to graph format...")
    preprocessor.export_to_graph_format('./graph_data')
    print("\n✓ PREPROCESSING COMPLETE")
