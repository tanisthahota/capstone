#!/usr/bin/env python3
"""
Graph Builder for Network Traffic Analysis
Converts CIC-IDS dataset into graph structure with IP addresses as nodes and traffic flows as edges.
"""

import numpy as np
import pandas as pd
import torch
from torch_geometric.data import Data
from typing import Dict, List, Tuple, Optional
import ipaddress
from collections import defaultdict, Counter
import re

class NetworkGraphBuilder:
    """Builds graph representation of network traffic data."""
    
    def __init__(self, classification_type='edge'):
        """
        Initialize the graph builder.
        
        Args:
            classification_type: 'edge' for edge classification, 'node' for node classification
        """
        self.ip_to_index = {}  
        self.index_to_ip = {}  # Maps node indices back to IP addresses
        self.classification_type = classification_type
        
        # Attack type mapping for consistent labeling
        self.attack_map = {
            'BENIGN': 0,
            'NORMAL': 0,
            'DDOS': 1,
            'DOS HULK': 2,
            'DOS GOLDENEYE': 3,
            'DOS SLOWHTTPTEST': 4,
            'DOS SLOWLORIS': 5,
            'PORTSCAN': 6,
            'WEB ATTACK – BRUTE FORCE': 7,
            'WEB ATTACK – XSS': 8,
            'WEB ATTACK – SQL INJECTION': 9,
            'BOTNET': 10,
            'INFILTRATION': 11,
            'HEARTBLEED': 12,
            'FTP-PATATOR': 13,
            'SSH-PATATOR': 14
        }
        
        self.internal_networks = [
            ipaddress.IPv4Network('192.168.0.0/16'),
            ipaddress.IPv4Network('10.0.0.0/8'),
            ipaddress.IPv4Network('172.16.0.0/12'),
            ipaddress.IPv4Network('127.0.0.0/8')
        ]
        
    def _extract_ip_from_address(self, address_str: str) -> Optional[str]:
        """Extract IP address from address:port format."""
        if pd.isna(address_str) or not isinstance(address_str, str):
            return None
        
        # Handle IPv4 format (IP:port)
        ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        match = re.search(ip_pattern, str(address_str))
        if match:
            return match.group(1)
        
        # If no port, assume it's just an IP
        try:
            ipaddress.ip_address(address_str)
            return address_str
        except:
            return None
    
    def _is_internal_ip(self, ip_str: str) -> bool:
        """Check if IP address is internal."""
        try:
            ip = ipaddress.ip_address(ip_str)
            for network in self.internal_networks:
                if ip in network:
                    return True
            return False
        except:
            return False
    
    def _normalize_attack_label(self, label: str) -> str:
        """Normalize attack labels to match our attack_map."""
        if pd.isna(label) or not isinstance(label, str):
            return 'BENIGN'
        
        label = str(label).upper().strip()
        
        # Handle common variations
        label_mappings = {
            'NORMAL': 'BENIGN',
            'DDOS ATTACK': 'DDOS',
            'DOS': 'DOS HULK',  # Default DOS type
            'WEB ATTACK - BRUTE FORCE': 'WEB ATTACK – BRUTE FORCE',
            'WEB ATTACK - XSS': 'WEB ATTACK – XSS', 
            'WEB ATTACK - SQL INJECTION': 'WEB ATTACK – SQL INJECTION',
            'BRUTE FORCE': 'WEB ATTACK – BRUTE FORCE',
            'XSS': 'WEB ATTACK – XSS',
            'SQL INJECTION': 'WEB ATTACK – SQL INJECTION'
        }
        
        # Apply mappings
        for pattern, replacement in label_mappings.items():
            if pattern in label:
                label = replacement
                break
        
        # Return label if it exists in attack_map, otherwise BENIGN
        return label if label in self.attack_map else 'BENIGN'
    
    def identify_unique_nodes(self, df: pd.DataFrame) -> List[str]:
        """
        🏗️ Step 2.1: Identify Unique Nodes
        Scan dataset and create unique list of all source and destination IP addresses.
        """
        print("🔍 Identifying unique IP addresses (nodes)...")
        
        # Extract source and destination IPs
        source_ips = set()
        dest_ips = set()
        
        # Common column names for source/destination
        src_columns = ['Source IP', 'Src IP', 'source_ip', 'src_ip']
        dst_columns = ['Destination IP', 'Dest IP', 'Dst IP', 'destination_ip', 'dest_ip', 'dst_ip']
        
        # Find the actual column names in the dataset
        src_col = None
        dst_col = None
        
        for col in src_columns:
            if col in df.columns:
                src_col = col
                break
        
        for col in dst_columns:
            if col in df.columns:
                dst_col = col
                break
        
        if not src_col or not dst_col:
            print(f"Available columns: {list(df.columns)}")
            raise ValueError("❌ Could not find source/destination IP columns in dataset")
        
        print(f"📊 Using columns: Source='{src_col}', Destination='{dst_col}'")
        
        # Extract IPs from the dataset
        for _, row in df.iterrows():
            src_ip = self._extract_ip_from_address(row[src_col])
            dst_ip = self._extract_ip_from_address(row[dst_col])
            
            if src_ip:
                source_ips.add(src_ip)
            if dst_ip:
                dest_ips.add(dst_ip)
        
        # Combine all unique IPs
        all_ips = source_ips.union(dest_ips)
        unique_ips = sorted(list(all_ips))
        
        # Create node index mapping
        for ip in unique_ips:
            self._get_or_create_node_index(ip)
        
        print(f"✅ Found {len(unique_ips)} unique IP addresses")
        print(f"   - Source IPs: {len(source_ips)}")
        print(f"   - Destination IPs: {len(dest_ips)}")
        print(f"   - Internal IPs: {sum(1 for ip in unique_ips if self._is_internal_ip(ip))}")
        print(f"   - External IPs: {sum(1 for ip in unique_ips if not self._is_internal_ip(ip))}")
        
        return unique_ips
    
    def aggregate_edges(self, df: pd.DataFrame) -> Dict[Tuple[int, int], Dict]:
        """
        🏗️ Step 2.2: Aggregate Edges
        Combine all flows between IP pairs into single representative edges.
        """
        print("🔗 Aggregating edges between IP pairs...")
        
        # Find column names
        src_columns = ['Source IP', 'Src IP', 'source_ip', 'src_ip']
        dst_columns = ['Destination IP', 'Dest IP', 'Dst IP', 'destination_ip', 'dest_ip', 'dst_ip']
        
        src_col = next((col for col in src_columns if col in df.columns), None)
        dst_col = next((col for col in dst_columns if col in df.columns), None)
        
        if not src_col or not dst_col:
            raise ValueError("❌ Could not find source/destination IP columns")
        
        # Edge aggregation dictionary
        edge_data = defaultdict(lambda: {
            'flow_count': 0,
            'total_bytes': 0,
            'total_fwd_bytes': 0,
            'total_bwd_bytes': 0,
            'avg_duration': 0,
            'total_duration': 0,
            'syn_count': 0,
            'fin_count': 0,
            'rst_count': 0,
            'ack_count': 0,
            'total_fwd_packets': 0,
            'total_bwd_packets': 0,
            'attack_flows': 0,  # Count of attack flows on this edge
            'attack_types': []  # List of attack types on this edge
        })
        
        # Feature column mappings (handle different naming conventions)
        feature_mappings = {
            'flow_duration': ['Flow Duration', 'flow_duration', 'Duration'],
            'fwd_bytes': ['Total Length of Fwd Packets', 'total_fwd_bytes', 'Fwd Bytes'],
            'bwd_bytes': ['Total Length of Bwd Packets', 'total_bwd_bytes', 'Bwd Bytes'],
            'syn_flag': ['SYN Flag Count', 'syn_flag_count', 'SYN Count'],
            'fin_flag': ['FIN Flag Count', 'fin_flag_count', 'FIN Count'],
            'rst_flag': ['RST Flag Count', 'rst_flag_count', 'RST Count'],
            'ack_flag': ['ACK Flag Count', 'ack_flag_count', 'ACK Count'],
            'fwd_packets': ['Total Fwd Packets', 'total_fwd_packets', 'Fwd Packets'],
            'bwd_packets': ['Total Backward Packets', 'total_bwd_packets', 'Bwd Packets'],
            'label': ['Label', 'label', 'Attack']
        }
        
        # Find actual column names
        actual_columns = {}
        for feature, possible_names in feature_mappings.items():
            for name in possible_names:
                if name in df.columns:
                    actual_columns[feature] = name
                    break
        
        print(f"📊 Using feature columns: {actual_columns}")
        
        # Process each flow
        processed_flows = 0
        for _, row in df.iterrows():
            src_ip = self._extract_ip_from_address(row[src_col])
            dst_ip = self._extract_ip_from_address(row[dst_col])
            
            if not src_ip or not dst_ip:
                continue
            
            src_idx = self._get_or_create_node_index(src_ip)
            dst_idx = self._get_or_create_node_index(dst_ip)
            
            # Use sorted tuple to treat edges as undirected
            edge_key = tuple(sorted([src_idx, dst_idx]))
            
            # Aggregate features
            edge_data[edge_key]['flow_count'] += 1
            
            # Duration
            if 'flow_duration' in actual_columns:
                duration = float(row.get(actual_columns['flow_duration'], 0))
                edge_data[edge_key]['total_duration'] += duration
            
            # Bytes
            if 'fwd_bytes' in actual_columns:
                fwd_bytes = float(row.get(actual_columns['fwd_bytes'], 0))
                edge_data[edge_key]['total_fwd_bytes'] += fwd_bytes
            
            if 'bwd_bytes' in actual_columns:
                bwd_bytes = float(row.get(actual_columns['bwd_bytes'], 0))
                edge_data[edge_key]['total_bwd_bytes'] += bwd_bytes
            
            edge_data[edge_key]['total_bytes'] = (
                edge_data[edge_key]['total_fwd_bytes'] + 
                edge_data[edge_key]['total_bwd_bytes']
            )
            
            # Packets
            if 'fwd_packets' in actual_columns:
                edge_data[edge_key]['total_fwd_packets'] += float(row.get(actual_columns['fwd_packets'], 0))
            
            if 'bwd_packets' in actual_columns:
                edge_data[edge_key]['total_bwd_packets'] += float(row.get(actual_columns['bwd_packets'], 0))
            
            # Flags
            for flag in ['syn_flag', 'fin_flag', 'rst_flag', 'ack_flag']:
                if flag in actual_columns:
                    flag_name = flag.replace('_flag', '_count')
                    edge_data[edge_key][flag_name] += float(row.get(actual_columns[flag], 0))
            
            # Attack classification
            if 'label' in actual_columns:
                label = self._normalize_attack_label(row.get(actual_columns['label'], ''))
                edge_data[edge_key]['attack_types'].append(label)
                if label != 'BENIGN':
                    edge_data[edge_key]['attack_flows'] += 1
            
            processed_flows += 1
        
        # Calculate averages and determine edge labels
        for edge_key, data in edge_data.items():
            if data['flow_count'] > 0:
                data['avg_duration'] = data['total_duration'] / data['flow_count']
                data['attack_ratio'] = data['attack_flows'] / data['flow_count']
                
                # Determine dominant attack type for edge classification
                if data['attack_types']:
                    attack_counter = Counter(data['attack_types'])
                    most_common_attack = attack_counter.most_common(1)[0][0]
                    data['edge_label'] = most_common_attack
                else:
                    data['edge_label'] = 'BENIGN'
            else:
                data['avg_duration'] = 0
                data['attack_ratio'] = 0
                data['edge_label'] = 'BENIGN'
        
        print(f"✅ Processed {processed_flows} flows into {len(edge_data)} unique edges")
        print(f"   - Average flows per edge: {processed_flows / len(edge_data):.2f}")
        
        return dict(edge_data)
    
    def define_node_features(self, df: pd.DataFrame, edge_data: Dict) -> Tuple[torch.Tensor, Optional[torch.Tensor]]:
        """
        🏗️ Step 2.3: Define Node Features
        Create features for each node (IP address) representing overall behavior.
        Returns node features and optionally node labels for node classification.
        """
        print("🎯 Defining node features...")
        
        num_nodes = len(self.ip_to_index)
        node_features = np.zeros((num_nodes, 6))  # 6 features per node
        
        # Initialize node statistics
        node_stats = defaultdict(lambda: {
            'total_packets_sent': 0,
            'total_packets_received': 0,
            'total_bytes_sent': 0,
            'total_bytes_received': 0,
            'connection_count': 0,
            'attack_involvement': 0,
            'attack_types': []  # For node classification
        })
        
        # Find column names
        src_columns = ['Source IP', 'Src IP', 'source_ip', 'src_ip']
        dst_columns = ['Destination IP', 'Dest IP', 'Dst IP', 'destination_ip', 'dest_ip', 'dst_ip']
        
        src_col = next((col for col in src_columns if col in df.columns), None)
        dst_col = next((col for col in dst_columns if col in df.columns), None)
        
        # Feature column mappings for flexible column names
        feature_mappings = {
            'fwd_packets': ['Total Fwd Packets', 'total_fwd_packets', 'Fwd Packets'],
            'bwd_packets': ['Total Backward Packets', 'total_bwd_packets', 'Bwd Packets'],
            'fwd_bytes': ['Total Length of Fwd Packets', 'total_fwd_bytes', 'Fwd Bytes'],
            'bwd_bytes': ['Total Length of Bwd Packets', 'total_bwd_bytes', 'Bwd Bytes'],
            'label': ['Label', 'label', 'Attack']
        }
        
        # Find actual column names
        actual_columns = {}
        for feature, possible_names in feature_mappings.items():
            for name in possible_names:
                if name in df.columns:
                    actual_columns[feature] = name
                    break
        
        # Aggregate node statistics from original flows
        for _, row in df.iterrows():
            src_ip = self._extract_ip_from_address(row[src_col])
            dst_ip = self._extract_ip_from_address(row[dst_col])
            
            if not src_ip or not dst_ip:
                continue
            
            # Get packet and byte counts
            fwd_packets = float(row.get(actual_columns.get('fwd_packets', 'Total Fwd Packets'), 0))
            bwd_packets = float(row.get(actual_columns.get('bwd_packets', 'Total Backward Packets'), 0))
            fwd_bytes = float(row.get(actual_columns.get('fwd_bytes', 'Total Length of Fwd Packets'), 0))
            bwd_bytes = float(row.get(actual_columns.get('bwd_bytes', 'Total Length of Bwd Packets'), 0))
            
            # Update source node stats
            node_stats[src_ip]['total_packets_sent'] += fwd_packets
            node_stats[src_ip]['total_packets_received'] += bwd_packets
            node_stats[src_ip]['total_bytes_sent'] += fwd_bytes
            node_stats[src_ip]['total_bytes_received'] += bwd_bytes
            node_stats[src_ip]['connection_count'] += 1
            
            # Update destination node stats
            node_stats[dst_ip]['total_packets_sent'] += bwd_packets
            node_stats[dst_ip]['total_packets_received'] += fwd_packets
            node_stats[dst_ip]['total_bytes_sent'] += bwd_bytes
            node_stats[dst_ip]['total_bytes_received'] += fwd_bytes
            
            # Check for attack involvement
            if 'label' in actual_columns:
                label = self._normalize_attack_label(row.get(actual_columns['label'], ''))
                if label != 'BENIGN':
                    node_stats[src_ip]['attack_involvement'] += 1
                    node_stats[dst_ip]['attack_involvement'] += 1
                    node_stats[src_ip]['attack_types'].append(label)
                    node_stats[dst_ip]['attack_types'].append(label)
        
        # Convert to feature matrix and create node labels if needed
        node_labels = None
        if self.classification_type == 'node':
            node_labels = np.zeros(num_nodes, dtype=int)
        
        for ip, idx in self.ip_to_index.items():
            stats = node_stats.get(ip, node_stats[ip])  # Use defaultdict
            
            node_features[idx, 0] = stats['total_packets_sent']
            node_features[idx, 1] = stats['total_packets_received']
            node_features[idx, 2] = stats['total_bytes_sent']
            node_features[idx, 3] = stats['total_bytes_received']
            node_features[idx, 4] = 1.0 if self._is_internal_ip(ip) else 0.0  # is_internal
            node_features[idx, 5] = stats['attack_involvement']
            
            # Assign node label based on dominant attack type
            if self.classification_type == 'node' and stats['attack_types']:
                attack_counter = Counter(stats['attack_types'])
                most_common_attack = attack_counter.most_common(1)[0][0]
                node_labels[idx] = self.attack_map.get(most_common_attack, 0)
        
        # Normalize features (log transform for heavy-tailed distributions)
        node_features[:, :4] = np.log1p(node_features[:, :4])  # log(1+x) for counts/bytes
        
        print(f"✅ Created node features matrix: {node_features.shape}")
        print(f"   - Features: [packets_sent, packets_received, bytes_sent, bytes_received, is_internal, attack_involvement]")
        
        if self.classification_type == 'node':
            print(f"   - Node labels created for node classification")
            return torch.tensor(node_features, dtype=torch.float32), torch.tensor(node_labels, dtype=torch.long)
        else:
            return torch.tensor(node_features, dtype=torch.float32), None
    
    def create_graph_object(self, df: pd.DataFrame) -> Data:
        """
        🏗️ Step 2.4: Create the Graph Object
        Assemble everything into a PyTorch Geometric Data object.
        """
        print("🔧 Creating PyTorch Geometric graph object...")
        
        # Step 1: Identify nodes
        unique_ips = self.identify_unique_nodes(df)
        
        # Step 2: Aggregate edges
        edge_data = self.aggregate_edges(df)
        
        # Step 3: Define node features
        node_features_result = self.define_node_features(df, edge_data)
        
        # Handle both node and edge classification cases
        if self.classification_type == 'node':
            node_features, node_labels = node_features_result
        else:
            node_features = node_features_result[0]
            node_labels = None
        
        # Step 4: Create edge index and edge attributes
        edge_list = []
        edge_attributes = []
        edge_labels = []  # For edge classification
        
        edge_feature_names = [
            'flow_count', 'total_bytes', 'avg_duration', 'syn_count', 
            'fin_count', 'total_fwd_packets', 'total_bwd_packets', 'attack_ratio'
        ]
        
        for (src_idx, dst_idx), data in edge_data.items():
            # Add both directions for undirected graph
            edge_list.extend([[src_idx, dst_idx], [dst_idx, src_idx]])
            
            # Edge features
            edge_attr = [
                data['flow_count'],
                data['total_bytes'],
                data['avg_duration'],
                data['syn_count'],
                data['fin_count'],
                data['total_fwd_packets'],
                data['total_bwd_packets'],
                data['attack_ratio']
            ]
            
            # Add same attributes for both directions
            edge_attributes.extend([edge_attr, edge_attr])
            
            # Edge labels for classification
            edge_label = self.attack_map.get(data['edge_label'], 0)
            edge_labels.extend([edge_label, edge_label])
        
        # Convert to tensors
        edge_index = torch.tensor(edge_list, dtype=torch.long).t().contiguous()
        edge_attr = torch.tensor(edge_attributes, dtype=torch.float32)
        
        # Apply log transformation to edge attributes (except attack_ratio)
        edge_attr[:, :-1] = torch.log1p(edge_attr[:, :-1])
        
        # Create the graph data object
        data_dict = {
            'x': node_features,
            'edge_index': edge_index,
            'edge_attr': edge_attr
        }
        
        # Add labels based on classification type
        if self.classification_type == 'edge':
            data_dict['y'] = torch.tensor(edge_labels, dtype=torch.long)
            print(f"   - Added edge labels for edge classification")
        elif self.classification_type == 'node':
            data_dict['y'] = node_labels
            print(f"   - Added node labels for node classification")
        
        data = Data(**data_dict)
        
        print(f"✅ Graph created successfully!")
        print(f"   - Nodes: {data.num_nodes}")
        print(f"   - Edges: {data.num_edges}")
        print(f"   - Node features: {data.num_node_features}")
        print(f"   - Edge features: {data.num_edge_features if hasattr(data, 'edge_attr') else 'None'}")
        print(f"   - Edge feature names: {edge_feature_names}")
        print(f"   - Classification type: {self.classification_type}")
        
        if hasattr(data, 'y'):
            print(f"   - Labels shape: {data.y.shape}")
            unique_labels = torch.unique(data.y)
            print(f"   - Unique labels: {unique_labels.tolist()}")
        
        return data
    
    def get_node_info(self) -> Dict:
        """Get information about the created nodes."""
        return {
            'ip_to_index': self.ip_to_index.copy(),
            'index_to_ip': self.index_to_ip.copy(),
            'total_nodes': len(self.ip_to_index)
        }
    
    def _get_or_create_node_index(self, ip: str) -> int:
        """Get node index for IP, create if doesn't exist."""
        if ip not in self.ip_to_index:
            index = len(self.ip_to_index)
            self.ip_to_index[ip] = index
            self.index_to_ip[index] = ip
        return self.ip_to_index[ip]


def demo_graph_builder():
    """Demonstration of the graph builder with sample data."""
    print("🚀 Graph Builder Demo")
    print("=" * 50)
    
    # Create sample data that mimics CIC-IDS format
    sample_data = {
        'Source IP': ['192.168.1.100:52301', '10.0.0.1:80', '8.8.8.8:53', '192.168.1.100:52302'],
        'Destination IP': ['8.8.8.8:53', '192.168.1.100:52301', '192.168.1.100:52301', '10.0.0.1:80'],
        'Flow Duration': [1500, 2000, 500, 3000],
        'Total Fwd Packets': [10, 5, 3, 15],
        'Total Backward Packets': [8, 7, 2, 12],
        'Total Length of Fwd Packets': [1200, 500, 300, 1800],
        'Total Length of Bwd Packets': [800, 700, 200, 1200],
        'SYN Flag Count': [1, 1, 0, 1],
        'FIN Flag Count': [1, 1, 1, 0],
        'Label': ['BENIGN', 'BENIGN', 'DDoS', 'BENIGN']
    }
    
    df = pd.DataFrame(sample_data)
    print("📊 Sample dataset:")
    print(df.to_string(index=False))
    print()
    
    # Test both edge and node classification
    print("\n🎯 Testing Edge Classification:")
    print("-" * 30)
    builder_edge = NetworkGraphBuilder(classification_type='edge')
    graph_data_edge = builder_edge.create_graph_object(df)
    
    print(f"Graph: {graph_data_edge}")
    print(f"Node features shape: {graph_data_edge.x.shape}")
    print(f"Edge index shape: {graph_data_edge.edge_index.shape}")
    print(f"Edge attributes shape: {graph_data_edge.edge_attr.shape}")
    print(f"Edge labels shape: {graph_data_edge.y.shape}")
    
    print("\n🎯 Testing Node Classification:")
    print("-" * 30)
    builder_node = NetworkGraphBuilder(classification_type='node')
    graph_data_node = builder_node.create_graph_object(df)
    
    print(f"Graph: {graph_data_node}")
    print(f"Node features shape: {graph_data_node.x.shape}")
    print(f"Node labels shape: {graph_data_node.y.shape}")
    
    # Show node mapping
    node_info = builder_edge.get_node_info()
    print(f"\n🔗 Node Mapping:")
    for ip, idx in node_info['ip_to_index'].items():
        internal = "Internal" if builder_edge._is_internal_ip(ip) else "External"
        print(f"   {idx}: {ip} ({internal})")


if __name__ == "__main__":
    demo_graph_builder()