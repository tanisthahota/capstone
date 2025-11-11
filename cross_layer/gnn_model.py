import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, GATConv, SAGEConv
from torch_geometric.nn import global_mean_pool, global_max_pool
from torch_geometric.data import Data, DataLoader
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import numpy as np

class CrossLayerThreatGNN(nn.Module):
    """
    GNN for detecting cross-layer threats in microservices.
    Works with homogeneous graphs from graph_builder.py
    """
    
    def __init__(self, input_dim=7, hidden_dim=64, num_layers=3, num_heads=4, dropout=0.3):
        super().__init__()
        
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.dropout = dropout
        
        # Input projection
        self.input_proj = nn.Linear(input_dim, hidden_dim)
        
        # Graph convolution layers (using GAT for attention)
        self.convs = nn.ModuleList()
        for i in range(num_layers):
            if i == 0:
                self.convs.append(GATConv(hidden_dim, hidden_dim, heads=num_heads, concat=False))
            else:
                self.convs.append(GATConv(hidden_dim, hidden_dim, heads=num_heads, concat=False))
        
        # Classification head
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, 2)  # Binary: benign vs malicious
        )
        
        # Anomaly detection head
        self.anomaly_head = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, 1),
            nn.Sigmoid()
        )
    
    def forward(self, data, return_anomaly=False):
        """
        Forward pass
        
        Args:
            data: PyG Data object with x, edge_index, batch
            return_anomaly: Whether to return anomaly scores
        
        Returns:
            logits: Classification logits [batch_size, 2]
            anomaly_scores: Anomaly scores [batch_size, 1] (optional)
        """
        x, edge_index, batch = data.x, data.edge_index, data.batch
        
        # Project input features
        x = self.input_proj(x)
        x = F.relu(x)
        
        # Apply graph convolutions
        for i, conv in enumerate(self.convs):
            x = conv(x, edge_index)
            x = F.relu(x)
            x = F.dropout(x, p=self.dropout, training=self.training)
        
        # Global pooling (aggregate node embeddings to graph level)
        graph_emb = global_mean_pool(x, batch)  # [batch_size, hidden_dim]
        
        # Classification
        logits = self.classifier(graph_emb)
        
        if return_anomaly:
            anomaly_scores = self.anomaly_head(graph_emb)
            return logits, anomaly_scores
        
        return logits


class ThreatDetectionTrainer:
    """Trainer for threat detection GNN"""
    
    def __init__(self, model, learning_rate=0.001, device='cuda' if torch.cuda.is_available() else 'cpu'):
        self.model = model.to(device)
        self.device = device
        self.optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate, weight_decay=1e-5)
        self.criterion = nn.CrossEntropyLoss()
        self.best_val_acc = 0
    
    def train_epoch(self, train_loader, epoch):
        """Train for one epoch"""
        self.model.train()
        total_loss = 0
        correct = 0
        total = 0
        
        for batch_idx, batch in enumerate(train_loader):
            batch = batch.to(self.device)
            
            # Forward pass
            self.optimizer.zero_grad()
            logits = self.model(batch)
            loss = self.criterion(logits, batch.y)
            
            # Backward pass
            loss.backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
            self.optimizer.step()
            
            # Metrics
            total_loss += loss.item()
            _, predicted = torch.max(logits, 1)
            total += batch.y.size(0)
            correct += (predicted == batch.y).sum().item()
        
        accuracy = 100 * correct / total
        avg_loss = total_loss / len(train_loader)
        
        return avg_loss, accuracy
    
    def evaluate(self, test_loader):
        """Evaluate on test set"""
        self.model.eval()
        correct = 0
        total = 0
        all_predictions = []
        all_labels = []
        all_anomaly_scores = []
        
        with torch.no_grad():
            for batch in test_loader:
                batch = batch.to(self.device)
                
                logits, anomaly_scores = self.model(batch, return_anomaly=True)
                _, predicted = torch.max(logits, 1)
                
                total += batch.y.size(0)
                correct += (predicted == batch.y).sum().item()
                
                all_predictions.extend(predicted.cpu().numpy())
                all_labels.extend(batch.y.cpu().numpy())
                all_anomaly_scores.extend(anomaly_scores.squeeze().cpu().numpy())
        
        accuracy = 100 * correct / total
        precision = precision_score(all_labels, all_predictions, zero_division=0)
        recall = recall_score(all_labels, all_predictions, zero_division=0)
        f1 = f1_score(all_labels, all_predictions, zero_division=0)
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'predictions': all_predictions,
            'labels': all_labels,
            'anomaly_scores': all_anomaly_scores
        }
    
    def detect_threat(self, graph, threshold=0.7):
        """Detect threat in single graph"""
        self.model.eval()
        
        with torch.no_grad():
            graph = graph.to(self.device)
            logits, anomaly_score = self.model(graph, return_anomaly=True)
            
            probs = F.softmax(logits, dim=1)
            threat_prob = probs[0][1].item()
            
            is_threat = threat_prob > threshold or anomaly_score.item() > threshold
            
            return {
                'is_threat': is_threat,
                'threat_probability': threat_prob,
                'anomaly_score': anomaly_score.item(),
                'confidence': max(probs[0]).item()
            }


if __name__ == "__main__":
    print("="*70)
    print("CROSS-LAYER THREAT DETECTION GNN")
    print("="*70)
    
    # Initialize model
    model = CrossLayerThreatGNN(
        input_dim=7,      # From graph_builder.py features
        hidden_dim=64,
        num_layers=3,
        num_heads=4,
        dropout=0.3
    )
    
    print(f"\nModel Parameters: {sum(p.numel() for p in model.parameters()):,}")
    print("\nArchitecture:")
    print(f"  - Input features: 7")
    print(f"  - Hidden dimension: 64")
    print(f"  - Graph attention layers: 3")
    print(f"  - Attention heads: 4")
    print(f"  - Output: Binary classification (benign/malicious)")
    
    # Initialize trainer
    trainer = ThreatDetectionTrainer(model, learning_rate=0.001)
    
    print("\nTrainer ready for:")
    print("  1. Training on graph batches")
    print("  2. Evaluation on test set")
    print("  3. Real-time threat detection")
    print("\n" + "="*70)