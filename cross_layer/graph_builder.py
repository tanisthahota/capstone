import torch
from torch_geometric.data import Data
import json
from typing import List, Tuple, Dict
import numpy as np

class CrossLayerGraphBuilder:
    """Build graphs from preprocessed nodes and edges"""
    
    def __init__(self):
        self.node_id_map = {}  # Maps original node_id to tensor index
    
    def load_preprocessed_data(self, nodes_file: str, edges_file: str):
        """Load nodes.jsonl and edges.jsonl"""
        nodes = []
        with open(nodes_file, 'r') as f:
            for line in f:
                nodes.append(json.loads(line))
        
        edges = []
        with open(edges_file, 'r') as f:
            for line in f:
                edge = json.loads(line)
                edges.append((edge['source'], edge['target'], edge['attributes']))
        
        print(f"Loaded {len(nodes)} nodes, {len(edges)} edges")
        return nodes, edges
    
    def build_graph(self, nodes: List[Dict], edges: List[Tuple]) -> Data:
        """Build homogeneous graph (simplest, works well for GNN)"""
        
        # Step 1: Extract features from nodes
        features = []
        for i, node in enumerate(nodes):
            self.node_id_map[node['node_id']] = i
            
            # Feature vector
            layer_map = {'application': 0, 'container': 1, 'network': 2, 'attack': 3}
            event_types = ['auth_attempt', 'auth_success', 'auth_failure', 'payment_process',
                          'privilege_escalation', 'reverse_shell', 'port_scan', 'dos_attack',
                          'brute_force', 'sql_injection', 'container_exec', 'network_connect', 'normal']
            
            feat = [
                layer_map.get(node['layer'], 0) / 4.0,  # Normalize layer
                event_types.index(node['event_type']) / len(event_types),  # Event type
                node['risk_score'],  # Risk score
                float(node['src_ip'] is not None),  # Has src_ip
                float(node['dst_ip'] is not None),  # Has dst_ip
                float(node['user_id'] is not None),  # Has user
                float(node['email'] is not None),  # Has email
            ]
            features.append(feat)
        
        # Step 2: Build edge index
        edge_index = []
        for src_id, dst_id, _ in edges:
            src_idx = self.node_id_map[src_id]
            dst_idx = self.node_id_map[dst_id]
            edge_index.append([src_idx, dst_idx])
        
        # Step 3: Create labels (benign=0, malicious=1)
        labels = []
        for node in nodes:
            attack_types = {'privilege_escalation', 'reverse_shell', 'port_scan',
                          'dos_attack', 'brute_force', 'sql_injection'}
            if node['risk_score'] > 0.6 or node['event_type'] in attack_types:
                labels.append(1)
            else:
                labels.append(0)
        
        # Step 4: Create PyG Data object
        graph = Data(
            x=torch.tensor(features, dtype=torch.float),
            edge_index=torch.tensor(edge_index, dtype=torch.long).t().contiguous() if edge_index else torch.zeros((2, 0), dtype=torch.long),
            y=torch.tensor(labels, dtype=torch.long),
            num_nodes=len(nodes)
        )
        
        return graph


if __name__ == "__main__":
    builder = CrossLayerGraphBuilder()
    graph_dir = r'c:\Users\tanis\Documents\PROJECTS\capstone\cross_layer\graph_data'
    nodes, edges = builder.load_preprocessed_data(f'{graph_dir}\\nodes.jsonl', f'{graph_dir}\\edges.jsonl')
    graph = builder.build_graph(nodes, edges)
    
    print(f"Graph: {graph}")
    print(f"Nodes: {graph.num_nodes}, Edges: {graph.num_edges}")
    print(f"Features: {graph.x.shape}")
    print(f"Labels: {(graph.y==0).sum()} benign, {(graph.y==1).sum()} malicious")