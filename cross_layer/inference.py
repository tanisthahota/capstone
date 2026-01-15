#!/usr/bin/env python3
"""
Real-Time Cross-Layer Aggregator
Consumes logs from all 3 layers and correlates them
"""

import json
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta
from kafka import KafkaConsumer
from threading import Thread
import torch
from gnn_model import CrossLayerThreatGNN
from graph_builder import CrossLayerGraphBuilder
from log_preprocessor import LogPreprocessor

class CrossLayerAggregator:
    def __init__(self):
        self.logs_buffer = defaultdict(list)
        self.correlation_window = 5
        self.gnn_inference_interval = 2
        self.model = CrossLayerThreatGNN(input_dim=7, hidden_dim=64, num_layers=3, num_heads=4)
        self.model.load_state_dict(torch.load('threat_detection_model.pt'))
        self.model.eval()
    
    def consume_container_logs(self):
        try:
            consumer = KafkaConsumer(
                'container-logs',
                bootstrap_servers='kafka:9092',
                auto_offset_reset='latest',
                value_deserializer=lambda v: json.loads(v.decode('utf-8')),
                group_id='cross-layer-container'
            )
            print("[Container Consumer] ✅ Connected")
            
            for message in consumer:
                log = message.value
                log['layer'] = 'container'
                log['received_at'] = datetime.utcnow().isoformat()
                self.logs_buffer['container'].append(log)
                
                cutoff = datetime.utcnow() - timedelta(seconds=self.correlation_window)
                self.logs_buffer['container'] = [
                    l for l in self.logs_buffer['container']
                    if datetime.fromisoformat(l['received_at']) > cutoff
                ]
                
                print(f"[Container] {log.get('action', 'N/A')[:40]}... | Buffer: {len(self.logs_buffer['container'])}")
        except Exception as e:
            print(f"[Container Consumer] ❌ Error: {e}")
    
    def consume_network_logs(self):
        try:
            consumer = KafkaConsumer(
                'network-logs',
                bootstrap_servers='kafka:9092',
                auto_offset_reset='latest',
                value_deserializer=lambda v: json.loads(v.decode('utf-8')),
                group_id='cross-layer-network'
            )
            print("[Network Consumer] ✅ Connected")
            
            for message in consumer:
                log = message.value
                log['layer'] = 'network'
                log['received_at'] = datetime.utcnow().isoformat()
                self.logs_buffer['network'].append(log)
                
                cutoff = datetime.utcnow() - timedelta(seconds=self.correlation_window)
                self.logs_buffer['network'] = [
                    l for l in self.logs_buffer['network']
                    if datetime.fromisoformat(l['received_at']) > cutoff
                ]
                
                print(f"[Network] {log.get('src_ip', 'N/A')} → {log.get('dst_ip', 'N/A')} | Buffer: {len(self.logs_buffer['network'])}")
        except Exception as e:
            print(f"[Network Consumer] ❌ Error: {e}")
    
    def consume_application_logs(self):
        try:
            consumer = KafkaConsumer(
                'application-logs',
                bootstrap_servers='kafka:9092',
                auto_offset_reset='latest',
                value_deserializer=lambda v: json.loads(v.decode('utf-8')),
                group_id='cross-layer-application'
            )
            print("[Application Consumer] ✅ Connected")
            
            for message in consumer:
                log = message.value
                log['layer'] = 'application'
                log['received_at'] = datetime.utcnow().isoformat()
                self.logs_buffer['application'].append(log)
                
                cutoff = datetime.utcnow() - timedelta(seconds=self.correlation_window)
                self.logs_buffer['application'] = [
                    l for l in self.logs_buffer['application']
                    if datetime.fromisoformat(l['received_at']) > cutoff
                ]
                
                print(f"[Application] {log.get('Method', 'N/A')} {log.get('URL', 'N/A')[:30]}... | Buffer: {len(self.logs_buffer['application'])}")
        except Exception as e:
            print(f"[Application Consumer] ❌ Error: {e}")
    
    def correlate_and_infer(self):
        preprocessor = LogPreprocessor()
        builder = CrossLayerGraphBuilder()
        
        while True:
            time.sleep(self.gnn_inference_interval)
            
            if not all(self.logs_buffer.values()):
                continue
            
            container_logs = self.logs_buffer['container'][-5:] if self.logs_buffer['container'] else []
            network_logs = self.logs_buffer['network'][-5:] if self.logs_buffer['network'] else []
            app_logs = self.logs_buffer['application'][-5:] if self.logs_buffer['application'] else []
            
            if not (container_logs and network_logs and app_logs):
                continue
            
            print(f"\n🔗 [CROSS-LAYER CORRELATION]")
            print(f"   Container: {len(container_logs)} | Network: {len(network_logs)} | Application: {len(app_logs)}")
            print(f"   Total: {len(container_logs) + len(network_logs) + len(app_logs)} logs\n")
            
            nodes = preprocessor.parse_logs(container_logs + network_logs + app_logs)
            edges = preprocessor.create_temporal_edges(nodes, time_window=10.0)
            edges.extend(preprocessor.create_cross_layer_edges(nodes))
            graph = builder.build_graph(nodes, edges)
            
            with torch.no_grad():
                logits = self.model(graph.x, graph.edge_index, node_level=True)
                probs = torch.softmax(logits, dim=1)
                threat_scores = probs[:, 1]  # Probability of malicious
                
                # Flag nodes with high threat score
                threats = (threat_scores > 0.7).nonzero(as_tuple=True)[0]
                print(f"Detected {len(threats)} suspicious nodes")
                for node_idx in threats[:10]:  # Show top 10
                    print(f"  Node {node_idx}: {threat_scores[node_idx]:.2%}")
    
    def start(self):
        print("\n🚀 [CROSS-LAYER AGGREGATOR] Starting...\n")
        
        threads = [
            Thread(target=self.consume_container_logs, daemon=True),
            Thread(target=self.consume_network_logs, daemon=True),
            Thread(target=self.consume_application_logs, daemon=True),
            Thread(target=self.correlate_and_infer, daemon=True)
        ]
        
        for thread in threads:
            thread.start()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[AGGREGATOR] 🛑 Shutting down...")
            sys.exit(0)

if __name__ == '__main__':
    aggregator = CrossLayerAggregator()
    aggregator.start()