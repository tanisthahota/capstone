#!/usr/bin/env python3
"""
Multi-Class Attack Detection Script using GraphSAGE with Network Topology
Takes CIC-IDS format input and builds realistic network graphs for attack detection.
"""

import os
import pickle
import random
import warnings
import argparse
import glob
from pathlib import Path
from typing import List, Dict, Tuple, Any

import numpy as np
import pandas as pd
import torch
import torch.nn.functional as F
from sklearn.metrics import classification_report, accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.neighbors import kneighbors_graph
from sklearn.preprocessing import StandardScaler, LabelEncoder
from torch_geometric.data import Data
from torch_geometric.nn import SAGEConv
from tqdm import tqdm

# Import our custom graph builder
from graph_builder import NetworkGraphBuilder

# --- Configuration ---
warnings.filterwarnings('ignore')

# Set random seeds for reproducibility
torch.manual_seed(42)
np.random.seed(42)
random.seed(42)
if torch.cuda.is_available():
    torch.cuda.manual_seed_all(42)

# Project directory configuration
BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "models"
DEFAULT_DATASET_DIR = Path(r"C:\Users\Admin\Downloads\archive (2)")

# Attack mapping for multi-class classification
ATTACK_MAPPING = {
    'BENIGN': 'BENIGN', 'Normal': 'BENIGN',
    'DDoS': 'DDoS',
    'DoS': 'DoS', 'DoS Hulk': 'DoS', 'DoS GoldenEye': 'DoS', 'DoS slowloris': 'DoS', 'DoS Slowhttptest': 'DoS', 'Heartbleed': 'DoS',
    'PortScan': 'PortScan',
    'FTP-Patator': 'Brute Force', 'SSH-Patator': 'Brute Force',
    'Web Attack  Brute Force': 'Web Attack', 'Web Attack  XSS': 'Web Attack', 'Web Attack  Sql Injection': 'Web Attack',
    'Bot': 'Botnet'
}

# --- Enhanced Model Definition ---
class AttackGraphSAGE(torch.nn.Module):
    """Enhanced GraphSAGE model for network attack classification with better architecture."""
    def __init__(self, node_features: int, edge_features: int, out_channels: int, hidden_channels: int = 64):
        super().__init__()
        # Node feature processing
        self.node_encoder = torch.nn.Linear(node_features, hidden_channels)
        
        # Edge feature processing (if available)
        self.edge_encoder = torch.nn.Linear(edge_features, hidden_channels // 2) if edge_features > 0 else None
        
        # GraphSAGE layers
        input_dim = hidden_channels + (hidden_channels // 2 if edge_features > 0 else 0)
        self.conv1 = SAGEConv(input_dim, hidden_channels)
        self.bn1 = torch.nn.BatchNorm1d(hidden_channels)
        
        self.conv2 = SAGEConv(hidden_channels, hidden_channels // 2)
        self.bn2 = torch.nn.BatchNorm1d(hidden_channels // 2)
        
        # Classification head
        self.classifier = torch.nn.Sequential(
            torch.nn.Linear(hidden_channels // 2, hidden_channels // 4),
            torch.nn.ReLU(),
            torch.nn.Dropout(0.5),
            torch.nn.Linear(hidden_channels // 4, out_channels)
        )

    def forward(self, data: Data) -> torch.Tensor:
        x, edge_index = data.x, data.edge_index
        
        # Encode node features
        x = self.node_encoder(x)
        x = F.relu(x)
        
        # Encode edge features if available and combine with node features
        if hasattr(data, 'edge_attr') and data.edge_attr is not None and self.edge_encoder is not None:
            edge_features = self.edge_encoder(data.edge_attr)
            # Average edge features for each node (simple aggregation)
            node_count = x.size(0)
            edge_agg = torch.zeros(node_count, edge_features.size(1), device=x.device)
            
            # Aggregate edge features to nodes
            for i in range(edge_index.size(1)):
                src, dst = edge_index[0, i], edge_index[1, i]
                edge_agg[src] += edge_features[i]
                edge_agg[dst] += edge_features[i]
            
            x = torch.cat([x, edge_agg], dim=1)
        
        # GraphSAGE layers
        x = self.conv1(x, edge_index)
        x = self.bn1(x)
        x = F.relu(x)
        x = F.dropout(x, p=0.3, training=self.training)
        
        x = self.conv2(x, edge_index)
        x = self.bn2(x)
        x = F.relu(x)
        x = F.dropout(x, p=0.5, training=self.training)
        
        # Classification
        x = self.classifier(x)
        return F.log_softmax(x, dim=1)

# --- Main Detector Class ---
class MultiAttackDetector:
    """Enhanced detector using network topology-based graphs."""
    def __init__(self, model_dir: Path = MODEL_DIR):
        self.model: AttackGraphSAGE | None = None
        self.label_encoder = LabelEncoder()
        self.graph_builder = NetworkGraphBuilder()
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.is_trained = False
        
        # Define file paths
        self.model_dir = model_dir
        self.model_dir.mkdir(exist_ok=True)
        self.model_path = self.model_dir / "chunchun.pth"
        self.encoder_path = self.model_dir / "label_encoder.pkl"
        self.graph_info_path = self.model_dir / "graph_info.pkl"

    def check_model_exists(self) -> bool:
        """Check if all required model files exist."""
        required_files = [self.model_path, self.encoder_path, self.graph_info_path]
        return all(f.exists() for f in required_files)

    def _load_and_combine_csvs(self, dataset_folder: Path) -> pd.DataFrame:
        """Loads and combines all CSV files from a given folder."""
        print(f"📁 Searching for CSV files in: {dataset_folder}")
        csv_files = list(dataset_folder.glob("*.csv"))
        if not csv_files:
            raise FileNotFoundError(f"❌ No CSV files found in the directory: {dataset_folder}")

        all_dfs = []
        for csv_file in csv_files:
            print(f"   - Loading: {csv_file.name}")
            try:
                df_temp = pd.read_csv(csv_file, encoding='utf-8', on_bad_lines='skip')
                df_temp.columns = df_temp.columns.str.strip()
                all_dfs.append(df_temp)
            except Exception as e:
                print(f"   ⚠️ Could not load {csv_file.name}: {e}")
        
        if not all_dfs:
            raise ValueError("❌ No valid data could be loaded.")
            
        combined_df = pd.concat(all_dfs, ignore_index=True)
        print(f"✅ Combined dataset shape: {combined_df.shape}")
        return combined_df

    def _preprocess_labels(self, df: pd.DataFrame) -> pd.DataFrame:
        """Preprocesses labels for multi-class classification with balanced sampling."""
        print("🔄 Preprocessing labels with balanced sampling...")
        
        # Clean data
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(inplace=True)

        label_col = 'Label'
        if label_col not in df.columns:
            raise ValueError(f"❌ Required column '{label_col}' not found in the dataset.")
        
        # Map to attack categories
        df['attack_category'] = df[label_col].map(ATTACK_MAPPING).fillna('Other')
        
        # Filter out categories with too few samples
        min_samples = 500 # Require at least 500 samples per category
        value_counts = df['attack_category'].value_counts()
        valid_categories = value_counts[value_counts >= min_samples].index.tolist()
        if 'Other' in valid_categories:
            valid_categories.remove('Other')
            
        print(f"🎯 Categories with sufficient samples (>={min_samples}): {valid_categories}")
        print(f"📊 Original category distribution:\n{value_counts}")
        
        # Balance the dataset by sampling exactly 500 samples from each valid category
        balanced_dfs = []
        samples_per_category = 500
        
        for category in valid_categories:
            category_df = df[df['attack_category'] == category]
            if len(category_df) >= samples_per_category:
                # Sample exactly 500 samples
                sampled_df = category_df.sample(n=samples_per_category, random_state=42)
                balanced_dfs.append(sampled_df)
                print(f"   ✅ {category}: sampled {samples_per_category} from {len(category_df)} available")
            else:
                print(f"   ⚠️ {category}: only {len(category_df)} samples available (skipping)")
        
        if not balanced_dfs:
            raise ValueError("❌ No categories have sufficient samples for balanced training.")
            
        df = pd.concat(balanced_dfs, ignore_index=True)
        
        # Shuffle the balanced dataset
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        print(f"🎯 Final balanced dataset:")
        print(f"   - Total samples: {len(df)}")
        print(f"   - Categories: {valid_categories}")
        print(f"📊 Balanced category distribution:\n{df['attack_category'].value_counts()}")
        
        return df

    def _create_train_test_split(self, df: pd.DataFrame, test_size: float = 0.2) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Creates train/test split while maintaining category balance."""
        print(f"🔀 Creating balanced train/test split ({test_size:.0%} test)...")
        
        # Split by attack category to maintain exact balance
        train_dfs = []
        test_dfs = []
        
        for category in df['attack_category'].unique():
            category_df = df[df['attack_category'] == category]
            
            
            # Split maintaining the balance: 400 train, 100 test
            train_size = int(len(category_df) * (1 - test_size))
            
            # Ensure we get exactly the right split
            train_part = category_df.iloc[:train_size]
            test_part = category_df.iloc[train_size:]
            
            train_dfs.append(train_part)
            test_dfs.append(test_part)
            
            print(f"   - {category}: {len(train_part)} train, {len(test_part)} test")
        
        train_df = pd.concat(train_dfs, ignore_index=True)
        test_df = pd.concat(test_dfs, ignore_index=True)
        
        # Shuffle while maintaining balance
        train_df = train_df.sample(frac=1, random_state=42).reset_index(drop=True)
        test_df = test_df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        print(f"📊 Final split results:")
        print(f"   - Training samples: {len(train_df)}")
        print(f"   - Testing samples: {len(test_df)}")
        print(f"📊 Training set balance:\n{train_df['attack_category'].value_counts()}")
        print(f"📊 Testing set balance:\n{test_df['attack_category'].value_counts()}")
        
        return train_df, test_df

    def _create_graph_with_labels(self, df: pd.DataFrame) -> Data:
        """Creates graph data with node labels for classification."""
        print("🏗️ Building flow-based graph for anonymized dataset...")
        
        # Check if we have IP columns
        ip_columns = ['Source IP', 'Src IP', 'source_ip', 'src_ip', 'Destination IP', 'Dest IP', 'Dst IP', 'destination_ip', 'dest_ip', 'dst_ip']
        has_ip_cols = any(col in df.columns for col in ip_columns)
        
        if has_ip_cols:
            # Use existing graph builder for datasets with IP addresses
            graph_data = self.graph_builder.create_graph_object(df)
            
            # Create node labels based on IP behavior (existing code)
            print("🎯 Assigning node labels based on IP behavior...")
            node_labels = []
            ip_to_index = self.graph_builder.get_node_info()['ip_to_index']
            
            for ip, node_idx in ip_to_index.items():
                src_col = next((col for col in ip_columns[:4] if col in df.columns), None)
                dst_col = next((col for col in ip_columns[4:] if col in df.columns), None)
                
                if src_col and dst_col:
                    def extract_ip(addr):
                        if pd.isna(addr):
                            return None
                        addr_str = str(addr)
                        import re
                        match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', addr_str)
                        return match.group(1) if match else addr_str
                    
                    ip_flows = df[
                        (df[src_col].apply(extract_ip) == ip) | 
                        (df[dst_col].apply(extract_ip) == ip)
                    ]
                    
                    if len(ip_flows) > 0:
                        attack_counts = ip_flows['attack_category'].value_counts()
                        majority_label = attack_counts.index[0]
                        node_labels.append(majority_label)
                    else:
                        node_labels.append('BENIGN')
                else:
                    node_labels.append('BENIGN')
        else:
            # Create synthetic graph for anonymized datasets
            print("🔄 No IP columns found - creating flow-based synthetic graph...")
            
            # Sample data for performance (but ensure we keep all data for prediction)
            df_sample = df.copy()
            
            # Define the key features that the model should focus on for attack detection
            # These are commonly used in network intrusion detection
            # Top 20 features per attack type

            priority_features = [
    'Flow Duration', 'Flow Bytes/s', 'Flow Packets/s', 'Total Fwd Packets', 'Total Length of Fwd Packets',
    'Average Packet Size', 'Fwd IAT Mean', 'Bwd IAT Mean', 'Active Mean', 'Idle Mean',
    'Fwd Packet Length Mean', 'Bwd Packet Length Mean', 'Fwd Packets/s', 'Bwd Packets/s',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
    'Fwd Header Length', 'Bwd Header Length', 'Packet Length Std', 'SYN Flag Count', 'FIN Flag Count',
    'RST Flag Count', 'ACK Flag Count', 'Subflow Fwd Bytes', 'Subflow Bwd Bytes', 'Destination Port',
    'Total Backward Packets', 'Packet Length Mean'
]

            
            # Use available columns that exist in the data
            available_features = [col for col in priority_features if col in df_sample.columns]
            
            # If we don't have enough priority features, add more numeric columns
            if len(available_features) < 6:
                numeric_cols = df_sample.select_dtypes(include=[np.number]).columns.tolist()
                additional_features = [col for col in numeric_cols if col not in available_features and col != 'attack_category']
                available_features.extend(additional_features[:max(0, 6 - len(available_features))])
            
            # Limit to exactly 6 features for consistency
            available_features = available_features[:6]
            
            # During prediction, use only the features that were used during training
            if hasattr(self, 'feature_names') and self.feature_names:
                # Use the exact same features as training
                available_features = [col for col in self.feature_names if col in df_sample.columns]
                if len(available_features) != len(self.feature_names):
                    missing_features = set(self.feature_names) - set(available_features)
                    print(f"⚠️ Warning: Missing features {missing_features}. Adding zeros.")
                    # Add missing features as zeros
                    for missing_feat in missing_features:
                        df_sample[missing_feat] = 0.0
                    available_features = self.feature_names
            
            print(f"🎯 Using {len(available_features)} features for graph construction:")
            for i, feat in enumerate(available_features):
                print(f"   {i+1}. {feat}")
            
            # Create node features (each flow becomes a node)
            node_features = df_sample[available_features].fillna(0).values
            
            # Store feature names for later use
            self.feature_names = available_features
            
            # Normalize features but save the scaler for prediction use
            if not hasattr(self, 'feature_scaler'):
                self.feature_scaler = StandardScaler()
                node_features = self.feature_scaler.fit_transform(node_features)
            else:
                node_features = self.feature_scaler.transform(node_features)
            
            # Create edges based on feature similarity (k-nearest neighbors)
            print("🔗 Creating edges based on flow similarity...")
            k = min(5, len(df_sample) - 1)  # Connect to 5 nearest neighbors
            if k > 0:
                knn_graph = kneighbors_graph(node_features, n_neighbors=k, mode='connectivity', include_self=False)
                
                # Convert to edge index format
                edge_indices = np.array(knn_graph.nonzero())
                edge_index = torch.tensor(edge_indices, dtype=torch.long)
                
                # Create edge features (difference in key metrics)
                edge_features = []
                for i in range(edge_indices.shape[1]):
                    src_idx, dst_idx = edge_indices[0, i], edge_indices[1, i]
                    src_features = node_features[src_idx]
                    dst_features = node_features[dst_idx]
                    edge_feat = np.abs(src_features - dst_features)[:4]  # Use first 4 features for edge
                    edge_features.append(edge_feat)
                
                edge_attr = torch.tensor(np.array(edge_features), dtype=torch.float)
            else:
                # If only one node, create self-loop
                edge_index = torch.tensor([[0], [0]], dtype=torch.long)
                edge_attr = torch.tensor([[0.0, 0.0, 0.0, 0.0]], dtype=torch.float)
            
            # Create the graph data object
            graph_data = Data(
                x=torch.tensor(node_features, dtype=torch.float),
                edge_index=edge_index,
                edge_attr=edge_attr
            )
            
            # Node labels are the attack categories for each flow
            node_labels = df_sample['attack_category'].tolist()
        
        # Encode labels
        if hasattr(self, 'label_encoder') and hasattr(self.label_encoder, 'classes_') and len(self.label_encoder.classes_) > 0:
            # Use existing encoder for prediction
            try:
                node_labels_encoded = self.label_encoder.transform(node_labels)
            except ValueError:
                # Handle unknown labels during prediction
                encoded_labels = []
                for label in node_labels:
                    if label in self.label_encoder.classes_:
                        encoded_labels.append(self.label_encoder.transform([label])[0])
                    else:
                        encoded_labels.append(0)  # Default to first class
                node_labels_encoded = np.array(encoded_labels)
        else:
            # Fit encoder during training
            node_labels_encoded = self.label_encoder.fit_transform(node_labels)
        
        graph_data.y = torch.tensor(node_labels_encoded, dtype=torch.long)
        
        print(f"✅ Graph created with {graph_data.num_nodes} nodes and {graph_data.num_edges} edges")
        print(f"   - Node features: {graph_data.num_node_features}")
        print(f"   - Edge features: {graph_data.num_edge_features if hasattr(graph_data, 'edge_attr') else 0}")
        print(f"   - Classes: {list(self.label_encoder.classes_)}")
        
        return graph_data

    def _run_training_loop(self, train_data: Data, test_data: Data, epochs: int = 100):
        """Enhanced training loop with proper evaluation and balanced class weights."""
        num_classes = len(self.label_encoder.classes_)
        
        self.model = AttackGraphSAGE(
            node_features=train_data.num_node_features,
            edge_features=train_data.num_edge_features if hasattr(train_data, 'edge_attr') else 0,
            out_channels=num_classes,
            hidden_channels=128
        ).to(self.device)
        
        # Calculate class weights for balanced training
        from sklearn.utils.class_weight import compute_class_weight
        
        # Get class counts from training data
        train_labels_np = train_data.y.cpu().numpy()
        class_weights = compute_class_weight(
            'balanced',
            classes=np.arange(num_classes),
            y=train_labels_np
        )
        class_weights_tensor = torch.tensor(class_weights, dtype=torch.float, device=self.device)
        
        print(f"📊 Using balanced class weights:")
        for i, (class_name, weight) in enumerate(zip(self.label_encoder.classes_, class_weights)):
            print(f"   - {class_name}: {weight:.4f}")
        
        optimizer = torch.optim.Adam(self.model.parameters(), lr=0.001, weight_decay=1e-4)
        scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=10, factor=0.5)
        criterion = torch.nn.NLLLoss(weight=class_weights_tensor)

        print(f"🚀 Starting enhanced training for {epochs} epochs...")
        best_test_acc = 0
        
        for epoch in tqdm(range(epochs), desc="Training Progress"):
            # Training
            self.model.train()
            optimizer.zero_grad()
            out = self.model(train_data)
            loss = criterion(out, train_data.y)
            loss.backward()
            optimizer.step()
            
            # Validation every 10 epochs
            if epoch % 10 == 0:
                self.model.eval()
                with torch.no_grad():
                    test_out = self.model(test_data)
                    test_pred = test_out.argmax(dim=1)
                    test_acc = (test_pred == test_data.y).float().mean().item()
                    
                    if test_acc > best_test_acc:
                        best_test_acc = test_acc
                    
                    scheduler.step(loss)
                    
                    if epoch % 20 == 0:
                        print(f"Epoch {epoch}: Loss={loss:.4f}, Test Acc={test_acc:.4f}")
        
        # Final evaluation with per-class metrics
        self.model.eval()
        with torch.no_grad():
            test_pred_logits = self.model(test_data)
            test_pred = test_pred_logits.argmax(dim=1).cpu().numpy()
            test_true = test_data.y.cpu().numpy()
        
        print("\n" + "="*50)
        print("📊 Final Test Results:")
        print(f"Best Test Accuracy: {best_test_acc:.4f}")
        print(f"Final Test Accuracy: {accuracy_score(test_true, test_pred):.4f}")
        print("\n📋 Classification Report:")
        print(classification_report(test_true, test_pred, target_names=self.label_encoder.classes_))
        
        # Per-class accuracy to check for overfitting
        print("\n📊 Per-class accuracy:")
        for i, class_name in enumerate(self.label_encoder.classes_):
            class_mask = test_true == i
            if class_mask.sum() > 0:
                class_acc = (test_pred[class_mask] == test_true[class_mask]).mean()
                print(f"   - {class_name}: {class_acc:.4f} ({class_mask.sum()} samples)")
        print("="*50)

    def train_model(self, dataset_folder: Path, epochs: int = 100):
        """Enhanced training pipeline using network topology."""
        print("🎯 Starting Enhanced Network Topology Training with Balanced Sampling")
        print("="*50)
        
        # Load and preprocess data
        df = self._load_and_combine_csvs(dataset_folder)
        df = self._preprocess_labels(df)
        
        # Verify balanced sampling
        print("\n🔍 Verifying balanced dataset:")
        category_counts = df['attack_category'].value_counts()
        print(f"📊 Attack category distribution after balancing:")
        for category, count in category_counts.items():
            print(f"   - {category}: {count} samples")
         
        # Check if all categories have exactly 500 samples
        if not all(count == 500 for count in category_counts.values):
            print("⚠️ Warning: Not all categories have exactly 500 samples!")
        else:
            print("✅ Perfect balance achieved: 500 samples per category")
        
        # Create train/test split
        train_df, test_df = self._create_train_test_split(df)
        
        # Verify training set balance
        print("\n🔍 Verifying training set balance:")
        train_counts = train_df['attack_category'].value_counts()
        print(f"📊 Training set distribution:")
        for category, count in train_counts.items():
            print(f"   - {category}: {count} samples")
        
        # Create graphs
        train_data = self._create_graph_with_labels(train_df).to(self.device)
        test_data = self._create_graph_with_labels(test_df).to(self.device)
        
        # Training
        self._run_training_loop(train_data, test_data, epochs)
        
        self.is_trained = True
        self.save_model()

    def predict_flow(self, flow_data: pd.DataFrame) -> Dict[str, Any]:
        """Predicts attack type for network flow data."""
        if not self.is_trained:
            raise RuntimeError("❌ Model is not loaded or trained.")
        
        # Create graph from flow data
        if len(flow_data) == 1:
            # Single flow prediction - need to create a minimal graph
            # Duplicate the flow a few times to create neighbors for graph structure
            flow_data = pd.concat([flow_data] * 5, ignore_index=True)
            target_node = 0  # The original flow is at index 0
        else:
            target_node = 0  # Predict for the first flow
        
        graph_data = self._create_graph_with_labels(flow_data).to(self.device)
        
        # Make prediction
        self.model.eval()
        with torch.no_grad():
            predictions = self.model(graph_data)
            node_prediction = predictions[target_node]
            probabilities = torch.exp(node_prediction).cpu().numpy()
        
        predicted_class_idx = probabilities.argmax()
        label = self.label_encoder.classes_[predicted_class_idx]
        confidence = probabilities[predicted_class_idx]

        return {
            'prediction': label,
            'attack_type': label if label != 'BENIGN' else 'None',
            'is_attack': label != 'BENIGN',
            'confidence': float(confidence),  # Return raw numeric confidence
            'all_probabilities': {name: float(prob) for name, prob in zip(self.label_encoder.classes_, probabilities)}
        }

    def predict_ip_behavior(self, ip_address: str, context_data: pd.DataFrame) -> Dict[str, Any]:
        """Predicts behavior for a specific IP address given context."""
        if not self.is_trained:
            raise RuntimeError("❌ Model is not loaded or trained.")
        
        # Check if we have IP columns
        ip_columns = ['Source IP', 'Src IP', 'source_ip', 'src_ip', 'Destination IP', 'Dest IP', 'Dst IP', 'destination_ip', 'dest_ip', 'dst_ip']
        has_ip_cols = any(col in context_data.columns for col in ip_columns)
        
        if not has_ip_cols:
            return {
                'error': 'IP-based prediction requires datasets with IP address columns. Use predict_flow() instead for anonymized data.'
            }
        
        # Build graph from context data
        graph_data = self.graph_builder.create_graph_object(context_data).to(self.device)
        
        # Find the IP in the graph
        ip_to_index = self.graph_builder.get_node_info()['ip_to_index']
        if ip_address not in ip_to_index:
            return {
                'prediction': 'UNKNOWN',
                'confidence': '0.0000',
                'message': f"IP {ip_address} not found in the provided context data"
            }
        
        node_idx = ip_to_index[ip_address]
        
        # Make prediction
        self.model.eval()
        with torch.no_grad():
            predictions = self.model(graph_data)
            node_prediction = predictions[node_idx]
            probabilities = torch.exp(node_prediction).cpu().numpy()
        
        predicted_class_idx = probabilities.argmax()
        label = self.label_encoder.classes_[predicted_class_idx]
        confidence = probabilities[predicted_class_idx]

        return {
            'ip_address': ip_address,
            'prediction': label,
            'attack_type': label if label != 'BENIGN' else 'None',
            'is_attack': label != 'BENIGN',
            'confidence': f"{confidence:.4f} ({confidence*100:.2f}%)",
            'all_probabilities': {name: f"{prob:.4f}" for name, prob in zip(self.label_encoder.classes_, probabilities)}
        }

    def predict(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Flexible prediction method that handles both IP-based and flow-based predictions."""
        if 'ip_address' in input_data and 'context_data' in input_data:
            return self.predict_ip_behavior(input_data['ip_address'], input_data['context_data'])
        elif 'flow_data' in input_data:
            return self.predict_flow(input_data['flow_data'])
        else:
            return {
                'error': 'Provide either: 1) ip_address + context_data (DataFrame) for IP-based prediction, or 2) flow_data (DataFrame) for flow-based prediction'
            }

    def save_model(self):
        """Saves the trained model and preprocessing objects."""
        if not self.is_trained:
            raise RuntimeError("❌ Cannot save a model that has not been trained.")
        
        print(f"💾 Saving enhanced model to {self.model_dir}...")
        
        # Ensure model directory exists
        self.model_dir.mkdir(exist_ok=True)
        
        # Save model state dict
        torch.save(self.model.state_dict(), self.model_path)
        print(f"   ✅ Model saved to: {self.model_path}")
        
        # Save label encoder
        with open(self.encoder_path, 'wb') as f:
            pickle.dump(self.label_encoder, f)
        print(f"   ✅ Label encoder saved to: {self.encoder_path}")
        
        # Save graph builder info (may be empty for flow-based graphs)
        try:
            graph_info = self.graph_builder.get_node_info()
        except:
            graph_info = {'ip_to_index': {}, 'index_to_ip': {}}
        
        # Add feature scaler and feature names to graph info for flow-based models
        if hasattr(self, 'feature_scaler'):
            graph_info['feature_scaler'] = self.feature_scaler
        if hasattr(self, 'feature_names'):
            graph_info['feature_names'] = self.feature_names
        
        with open(self.graph_info_path, 'wb') as f:
            pickle.dump(graph_info, f)
        print(f"   ✅ Graph info saved to: {self.graph_info_path}")
        
        print("✅ Enhanced model saved successfully!")
        print(f"📁 Model files location: {self.model_dir}")
        print(f"   - Model: {self.model_path.name}")
        print(f"   - Encoder: {self.encoder_path.name}")
        print(f"   - Graph Info: {self.graph_info_path.name}")

    def load_model(self) -> bool:
        """Loads a pre-trained model and preprocessing objects."""
        if not self.check_model_exists():
            return False
            
        print(f"📂 Loading enhanced model from {self.model_dir}...")
        try:
            # Load preprocessing objects
            with open(self.encoder_path, 'rb') as f:
                self.label_encoder = pickle.load(f)
            
            with open(self.graph_info_path, 'rb') as f:
                graph_info = pickle.load(f)
            
            # Reconstruct graph builder state (might be empty for flow-based models)
            if 'ip_to_index' in graph_info and 'index_to_ip' in graph_info:
                self.graph_builder.ip_to_index = graph_info['ip_to_index']
                self.graph_builder.index_to_ip = graph_info['index_to_ip']
            
            # Load feature scaler and feature names for flow-based models
            if 'feature_scaler' in graph_info:
                self.feature_scaler = graph_info['feature_scaler']
            if 'feature_names' in graph_info:
                self.feature_names = graph_info['feature_names']
            
            # Create model with proper dimensions
            num_classes = len(self.label_encoder.classes_)
            
            # Try to load model state dict to determine input dimensions
            state_dict = torch.load(self.model_path, map_location=self.device)
            
            # Extract dimensions from saved model
            node_features = state_dict['node_encoder.weight'].shape[1]
            edge_features = 0
            if 'edge_encoder.weight' in state_dict:
                edge_features = state_dict['edge_encoder.weight'].shape[1]
            
            # Create model with correct dimensions
            self.model = AttackGraphSAGE(
                node_features=node_features,
                edge_features=edge_features,
                out_channels=num_classes,
                hidden_channels=128
            ).to(self.device)
            
            # Load model state
            self.model.load_state_dict(state_dict)
            
            self.is_trained = True
            print("✅ Enhanced model loaded successfully!")
            print(f"   - Attack Classes: {list(self.label_encoder.classes_)}")
            print(f"   - Node features: {node_features}")
            print(f"   - Edge features: {edge_features}")
            return True
            
        except Exception as e:
            print(f"❌ Error loading enhanced model: {e}")
            return False

def main():
    """Enhanced main function with automatic model loading."""
    parser = argparse.ArgumentParser(description='Enhanced Multi-Attack Detection using Network Topology GraphSAGE')
    parser.add_argument('--train', action='store_true', help='Force training even if a model exists.')
    parser.add_argument('--dataset', type=Path, default=DEFAULT_DATASET_DIR, help=f'Path to the dataset folder.')
    parser.add_argument('--epochs', type=int, default=100, help='Number of training epochs.')
    
    args = parser.parse_args()
    
    detector = MultiAttackDetector()

    # Check if model exists and load it automatically
    if detector.check_model_exists() and not args.train:
        print("🎯 Pre-trained model found! Loading existing model...")
        if detector.load_model():
            print("✅ Model loaded successfully! Ready for predictions.")
            print("\n" + "="*50)
            print("🎯 Enhanced Network Topology Attack Detection Ready!")
            print("="*50)
            print("💡 This model uses realistic network topology!")
            print("   - Nodes represent IP addresses or flows")
            print("   - Edges represent communication patterns")
            print("   - Features capture network behavior")
            print("\n🔍 Ready for predictions!")
            return
        else:
            print("❌ Failed to load existing model. Will train a new one...")
            args.train = True
    elif not args.train:
        print("🤔 No existing model found.")
        print("💡 To train a model, run with --train flag:")
        print(f"   python {__file__} --train")
        return

    # Train model only if explicitly requested
    if args.train:
        if not args.dataset.exists():
            print(f"❌ Dataset directory not found at: {args.dataset}")
            return
        
        print("🔄 Starting training...")
        detector.train_model(dataset_folder=args.dataset, epochs=args.epochs)

        print("\n" + "="*50)
        print("🎯 Enhanced Network Topology Attack Detection Ready!")
        print("="*50)
        print("💡 This model uses realistic network topology!")
        print("   - Nodes represent IP addresses or flows")
        print("   - Edges represent communication patterns")
        print("   - Features capture network behavior")
        print("\n🔍 Ready for predictions!")

def test_sample():
    """Test the model with the specific DDoS sample provided."""
    print("\n" + "="*60)
    print("🎯 Testing with Specific DDoS Sample")
    print("="*60)
    
    sample_traffic = {
    'Destination Port': 443,
    'Flow Duration': 60365575,               # ~60.36 seconds
    'Total Fwd Packets': 14,
    'Total Backward Packets': 12,
    'Total Length of Fwd Packets': 856,      # bytes
    'Total Length of Bwd Packets': 3210,     # bytes
    'Fwd Packet Length Mean': 61.14285714,
    'Fwd Packet Length Std': 148.7868156,
    'Bwd Packet Length Mean': 267.5,
    'Bwd Packet Length Std': 553.3369021,
    'Flow Bytes/s': 67.35627052,             # total_bytes / duration
    'Flow Packets/s': 0.430709059,           # total_packets / duration
    'Flow IAT Mean': 2414623.0,
    'Flow IAT Std': 4350649.777,
    'Flow Active Mean': 10200000.0,
    'Flow Active Std': 14.0,
    'Flow Idle Mean': 60400000.0,
    'Flow Idle Std': 4643505.769,
    'Fwd Packets/s': 5202588.785,
    'Bwd Packets/s': 10200000.0,
    'Fwd Header Length': 378.0,
    'Bwd Header Length': 60300000.0,
    'Average Packet Size': 5483098.455,
    'Packet Length Mean': 5239338.008,
    'Packet Length Std': 10200000.0,
    'FIN Flag Count': 0,
    'SYN Flag Count': 0,
    'RST Flag Count': 0,
    'ACK Flag Count': 0,
    'PSH Flag Count': 0,
    'URG Flag Count': 0,
    'Average Fwd Segment Size': 150.5925926,
    'Average Bwd Segment Size': 389.9946015,
    'Flow Duration Std': 152095.7892,
    'Fwd IAT Mean': 156.3846154,
    'Fwd IAT Std': 61.14285714,
    'Bwd IAT Mean': 267.5,
    'Bwd IAT Std': 456.0,
    'Init_Win_bytes_forward': 29200,
    'Init_Win_bytes_backward': 123,
    'Fwd Seg Size Min': 3,
    'Bwd Seg Size Min': 32,
    'Fwd Act Data Pkts': 69667,
    'Fwd Seg Size Avg': 46087.63757,
    'Fwd Seg Size Std': 163742.0,
    'Bwd Seg Size Avg': 50599.0,
    'Fwd Header Max': 9991166.833,
    'Bwd Header Max': 463609.9178,
    'Flow Bytes Avg': 10200000,
    'Flow Bytes Total': 9045547,
    'Label': 'BENIGN'
}






    # Load the detector
    detector = MultiAttackDetector()
    if not detector.load_model():
        print("❌ No trained model found. Please train the model first.")
        return
    
    # Create DataFrame and add attack_category for testing
    df = pd.DataFrame([sample_traffic])
    df['attack_category'] = ''  # Set expected label for testing

    print("📋 Input DDoS Sample Features:")
    for key, value in sample_traffic.items():
        print(f"   - {key}: {value}")
    
    try:
        # Make prediction
        result = detector.predict({'flow_data': df})
        
        print(f"\n🔍 PREDICTION RESULTS:")
        print(f"   🎯 Predicted Class: {result['prediction']}")
        print(f"   ⚡ Attack Type: {result['attack_type']}")
        print(f"   🚨 Is Attack: {'YES' if result['is_attack'] else 'NO'}")
        print(f"   📈 Confidence: {result['confidence']:.4f} ({result['confidence']*100:.2f}%)")
        
        if 'all_probabilities' in result:
            print(f"\n📊 All Class Probabilities:")
            sorted_probs = sorted(result['all_probabilities'].items(), 
                                key=lambda x: x[1], reverse=True)
            for class_name, prob in sorted_probs:
                print(f"      - {class_name}: {prob:.4f} ({prob*100:.2f}%)")
            
    except Exception as e:
        print(f"❌ Error during prediction: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
    # Test the sample if model is available
    detector = MultiAttackDetector()
    if detector.check_model_exists():
        test_sample()