import torch
from torch_geometric.data import Data, DataLoader
from torch_geometric.loader import DataLoader as PyGDataLoader
from gnn_model import CrossLayerThreatGNN, ThreatDetectionTrainer
from graph_builder import CrossLayerGraphBuilder
import json

# Load preprocessed data
builder = CrossLayerGraphBuilder()
graph_dir = r'c:\Users\tanis\Documents\PROJECTS\capstone\cross_layer\graph_data'
nodes, edges = builder.load_preprocessed_data(f'{graph_dir}\\nodes.jsonl', f'{graph_dir}\\edges.jsonl')

# Build graph
graph = builder.build_graph(nodes, edges)

print(f"Graph: {graph}")
print(f"Nodes: {graph.num_nodes}, Edges: {graph.num_edges}")
print(f"Features: {graph.x.shape}")
print(f"Labels: {(graph.y==0).sum()} benign, {(graph.y==1).sum()} malicious")

# Create simple train/test split
from sklearn.model_selection import train_test_split

# Split nodes by label
benign_indices = (graph.y == 0).nonzero(as_tuple=True)[0].tolist()
malicious_indices = (graph.y == 1).nonzero(as_tuple=True)[0].tolist()

train_benign = benign_indices[:int(0.8*len(benign_indices))]
test_benign = benign_indices[int(0.8*len(benign_indices)):]

train_malicious = malicious_indices[:int(0.8*len(malicious_indices))]
test_malicious = malicious_indices[int(0.8*len(malicious_indices)):]

train_mask = torch.zeros(graph.num_nodes, dtype=torch.bool)
test_mask = torch.zeros(graph.num_nodes, dtype=torch.bool)

train_mask[train_benign + train_malicious] = True
test_mask[test_benign + test_malicious] = True

graph.train_mask = train_mask
graph.test_mask = test_mask

# Initialize model and trainer
model = CrossLayerThreatGNN(input_dim=7, hidden_dim=64, num_layers=3, num_heads=4)
trainer = ThreatDetectionTrainer(model, learning_rate=0.001)

# Move graph to same device as model
device = trainer.device
graph = graph.to(device)

print(f"\nUsing device: {device}")

# Train
print("\n" + "="*70)
print("TRAINING")
print("="*70)

num_epochs = 50
for epoch in range(num_epochs):
    model.train()
    
    # Forward pass on entire graph (node-level classification)
    logits = model(graph.x, graph.edge_index, node_level=True)  # [num_nodes, 2]
    loss = trainer.criterion(logits[train_mask], graph.y[train_mask])
    
    trainer.optimizer.zero_grad()
    loss.backward()
    torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
    trainer.optimizer.step()
    
    if epoch % 10 == 0:
        print(f"Epoch {epoch}: Loss = {loss.item():.4f}")

print("\n" + "="*70)
print("EVALUATION")
print("="*70)

# Evaluate
model.eval()
with torch.no_grad():
    logits = model(graph.x, graph.edge_index, node_level=True)  # [num_nodes, 2]
    test_logits = logits[test_mask.to(device)]
    test_labels = graph.y[test_mask.to(device)]
    
    _, predictions = torch.max(test_logits, 1)
    accuracy = (predictions == test_labels).sum().item() / len(test_labels)
    
    print(f"\nTest Accuracy: {accuracy*100:.2f}%")
    print(f"Correct: {(predictions == test_labels).sum().item()}/{len(test_labels)}")
    
    # Additional metrics
    from sklearn.metrics import precision_score, recall_score, f1_score
    precision = precision_score(test_labels.cpu().numpy(), predictions.cpu().numpy(), zero_division=0)
    recall = recall_score(test_labels.cpu().numpy(), predictions.cpu().numpy(), zero_division=0)
    f1 = f1_score(test_labels.cpu().numpy(), predictions.cpu().numpy(), zero_division=0)
    
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1 Score: {f1:.4f}")
    print("\n" + "="*70)
    print("✓ TRAINING COMPLETE")
    print("="*70)
    
trainer.save_model('threat_detection_model.pt')