import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from peft import PeftModel
import os
import json

class SLMInference:
    """Load and run inference on trained SLM models with lazy loading"""
    
    def __init__(self, model_dir="./", layer=None):
        """
        Initialize SLM inference with optional lazy loading
        
        Args:
            model_dir: Base directory containing model folders
            layer: Optional - load only this specific layer ('application', 'container', or 'network')
                   If None, models are loaded on-demand when predict() is called
        """
        self.model_dir = model_dir
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.models = {}
        self.tokenizers = {}
        self.threat_labels = {}
        
        # Layer configurations
        self.layer_config = {
            "application": {
                "path": os.path.join(model_dir, "application", "application_model"),
                "base_model": "answerdotai/ModernBERT-base",
                "is_lora": True,
                "num_labels": 3,
                "labels": ["benign", "sqli", "xss"]
            },
            "container": {
                "path": os.path.join(model_dir, "container", "container_model"),
                "base_model": "answerdotai/ModernBERT-base",
                "is_lora": True,
                "num_labels": 3,
                "labels": ["benign", "reverse_shell", "priv_esc"]
            },
            "network": {
                "path": os.path.join(model_dir, "network", "network_model"),
                "base_model": "answerdotai/ModernBERT-base",  # Changed from distilbert
                "is_lora": True,
                "num_labels": 4,
                "labels": ["BENIGN", "BRUTE_FORCE", "DOS", "PORTSCAN"]
            }
        }
        
        # If specific layer is requested, load only that layer
        if layer:
            if layer not in self.layer_config:
                raise ValueError(f"Invalid layer: {layer}. Must be one of: {list(self.layer_config.keys())}")
            print(f"Loading model for {layer} layer only...")
            self.load_model(layer)
        else:
            print("SLM Inference initialized in lazy-loading mode.")
            print("Models will be loaded on-demand when predictions are requested.")
    
    def load_model(self, layer: str):
        """
        Load a specific layer's model
        
        Args:
            layer: 'application', 'container', or 'network'
        """
        if layer in self.models:
            print(f"Model for {layer} already loaded.")
            return
        
        if layer not in self.layer_config:
            raise ValueError(f"Invalid layer: {layer}")
        
        config = self.layer_config[layer]
        
        try:
            model_path = config["path"]
            
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"Model path not found for {layer}: {model_path}")
            
            if config["is_lora"]:
                # Load base model + LoRA adapter
                print(f"Loading {layer} model (LoRA adapter)...")
                base_model = AutoModelForSequenceClassification.from_pretrained(
                    config["base_model"],
                    num_labels=config["num_labels"]
                )
                model = PeftModel.from_pretrained(base_model, model_path)
            else:
                # Load full fine-tuned model directly
                print(f"Loading {layer} model (full fine-tuned)...")
                model = AutoModelForSequenceClassification.from_pretrained(
                    model_path,
                    local_files_only=True
                )
            
            model = model.to(self.device)
            model.eval()
            
            # Load tokenizer
            tokenizer = AutoTokenizer.from_pretrained(model_path)
            
            self.models[layer] = model
            self.tokenizers[layer] = tokenizer
            self.threat_labels[layer] = config["labels"]
            
            print(f"✓ Successfully loaded {layer} model from {model_path}")
            
        except Exception as e:
            print(f"✗ Error loading {layer} model: {e}")
            import traceback
            traceback.print_exc()
            raise
    
    def load_all_models(self):
        """Load all models at once (for batch processing across layers)"""
        print("Loading all layer models...")
        for layer in self.layer_config.keys():
            try:
                self.load_model(layer)
            except Exception as e:
                print(f"Warning: Could not load {layer} model: {e}")
    
    def predict(self, layer: str, text: str):
        """
        Get SLM prediction for a given layer and text
        
        Args:
            layer: 'application', 'container', or 'network'
            text: Input text to classify
        
        Returns:
            Dict with prediction, confidence, and label
        """
        
        # Validate layer
        if layer not in self.layer_config:
            return {
                "error": f"Invalid layer: {layer}. Must be one of: {list(self.layer_config.keys())}",
                "prediction": None,
                "confidence": 0,
                "label": "unknown"
            }
        
        # Load model if not already loaded (lazy loading)
        if layer not in self.models:
            print(f"Model for {layer} not loaded yet. Loading now...")
            try:
                self.load_model(layer)
            except Exception as e:
                return {
                    "error": f"Failed to load model for {layer}: {str(e)}",
                    "prediction": None,
                    "confidence": 0,
                    "label": "unknown"
                }
        
        try:
            model = self.models[layer]
            tokenizer = self.tokenizers[layer]
            labels = self.threat_labels[layer]
            
            # Tokenize input
            inputs = tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=512,
                padding=True
            ).to(self.device)
            
            # Get predictions
            with torch.no_grad():
                outputs = model(**inputs)
                logits = outputs.logits
                probabilities = torch.softmax(logits, dim=-1)
                prediction = torch.argmax(probabilities, dim=-1).item()
                confidence = probabilities[0][prediction].item()
            
            label = labels[prediction]
            
            return {
                "prediction": prediction,
                "confidence": confidence,
                "label": label,
                "probabilities": {labels[i]: probabilities[0][i].item() for i in range(len(labels))}
            }
        
        except Exception as e:
            return {
                "error": str(e),
                "prediction": None,
                "confidence": 0,
                "label": "unknown"
            }
    
    def predict_batch(self, layer: str, texts: list):
        """
        Get predictions for multiple texts from the same layer
        
        Args:
            layer: 'application', 'container', or 'network'
            texts: List of input texts to classify
        
        Returns:
            List of prediction dictionaries
        """
        # Ensure model is loaded for this layer
        if layer not in self.models:
            try:
                self.load_model(layer)
            except Exception as e:
                return [{
                    "error": f"Failed to load model for {layer}: {str(e)}",
                    "prediction": None,
                    "confidence": 0,
                    "label": "unknown"
                }] * len(texts)
        
        results = []
        for text in texts:
            result = self.predict(layer, text)
            results.append(result)
        return results
    
    def get_loaded_layers(self):
        """Return list of currently loaded layers"""
        return list(self.models.keys())
    
    def unload_model(self, layer: str):
        """
        Unload a specific layer's model to free memory
        
        Args:
            layer: 'application', 'container', or 'network'
        """
        if layer in self.models:
            del self.models[layer]
            del self.tokenizers[layer]
            del self.threat_labels[layer]
            
            # Force garbage collection
            import gc
            torch.cuda.empty_cache() if torch.cuda.is_available() else None
            gc.collect()
            
            print(f"✓ Unloaded {layer} model and freed memory")
        else:
            print(f"Model for {layer} is not currently loaded")


class SLMThreatMapper:
    """Map SLM predictions to threat types"""
    
    # Map SLM labels to threat names
    THREAT_MAPPING = {
        "application": {
            "sqli": "SQL Injection (SQLi)",
            "xss": "Cross-Site Scripting (XSS)",
            "benign": "Benign",
            "unknown": "Unknown"
        },
        "container": {
            "reverse_shell": "Reverse Shell",
            "priv_esc": "Privilege Escalation",
            "benign": "Benign",
            "unknown": "Unknown"
        },
        "network": {
            "BRUTE_FORCE": "Brute Force Attack",
            "brute_force": "Brute Force Attack",
            "PORTSCAN": "Port Scanning",
            "port_scan": "Port Scanning",
            "DOS": "Denial of Service (DoS)",
            "dos": "Denial of Service (DoS)",
            "BENIGN": "Benign",
            "benign": "Benign",
            "unknown": "Unknown"
        }
    }
    
    @staticmethod
    def map_to_threat_name(layer: str, label: str):
        """Convert SLM label to threat name"""
        if layer in SLMThreatMapper.THREAT_MAPPING:
            return SLMThreatMapper.THREAT_MAPPING[layer].get(label, label)
        return label


# Example usage
if __name__ == "__main__":
    # Example 1: Load only container layer
    print("\n=== Example 1: Load specific layer ===")
    slm = SLMInference(model_dir="/home/uday/Downloads/RAG", layer="container")
    result = slm.predict("container", "exec_create: /bin/bash -i")
    print(json.dumps(result, indent=2))
    
    # Example 2: Lazy loading (load on demand)
    print("\n=== Example 2: Lazy loading ===")  
    slm_lazy = SLMInference(model_dir="/home/uday/Downloads/RAG")
    
    # First prediction triggers loading
    result1 = slm_lazy.predict("application", "SELECT * FROM users WHERE id=1 OR 1=1")
    print(f"Application layer: {result1['label']}")
    
    # Second prediction uses already-loaded model
    result2 = slm_lazy.predict("application", "<script>alert('XSS')</script>")
    print(f"Application layer: {result2['label']}")
    
    # Different layer triggers new model loading
    result3 = slm_lazy.predict("network", "TCP SYN flood from 192.168.1.100")
    print(f"Network layer: {result3['label']}")
    
    print(f"\nCurrently loaded layers: {slm_lazy.get_loaded_layers()}")