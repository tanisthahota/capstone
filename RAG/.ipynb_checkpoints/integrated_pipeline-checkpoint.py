import json
import sys
import os
from pipeline import ThreatDetectionPipeline
from slm_integration import SLMInference, SLMThreatMapper

class IntegratedThreatDetectionPipeline:
    """Combines SLM classification with RAG fallback for unknown threats"""
    
    def __init__(self, model_dir="./", persist_dir="./chroma_db"):
        """Initialize RAG component only - SLM loaded on demand per layer"""
        print("Initializing Integrated Threat Detection Pipeline...")
        print("="*70)
        
        # Initialize RAG pipeline
        print("\n[1/2] Initializing RAG System...")
        self.rag_pipeline = ThreatDetectionPipeline(persist_dir)
        
        # Store model directory for lazy loading
        self.model_dir = model_dir
        self.slm = None
        self.loaded_layer = None
        
        print("\n" + "="*70)
        print("Pipeline initialized successfully!")
        print("SLM models will be loaded on-demand based on layer type.")
        print("="*70)
    
    def load_slm_for_layer(self, layer: str):
        """Load SLM model for specific layer if not already loaded"""
        if self.loaded_layer != layer or self.slm is None:
            print(f"\n[SLM] Loading model for {layer} layer...")
            self.slm = SLMInference(self.model_dir, layer=layer)
            self.loaded_layer = layer
            print(f"[SLM] {layer.capitalize()} layer model loaded successfully!")
    
    def extract_event_description(self, layer: str, event_data):
        """
        Extract meaningful text description from logs (JSON or plain text)
        
        Args:
            layer: 'application', 'container', or 'network'
            event_data: Raw log data (dict or string)
        
        Returns:
            Text description for SLM processing
        """
        
        # If input is already a string, return it directly
        if isinstance(event_data, str):
            return event_data
        
        # If input is dict, extract based on layer
        if layer == "container":
            status = event_data.get("status", "")
            action = event_data.get("Action", "")
            from_image = event_data.get("from", "")
            service = event_data.get("Actor", {}).get("Attributes", {}).get("com.docker.compose.service", "")
            
            description = f"{status or action}"
            if from_image:
                description += f" from {from_image}"
            if service:
                description += f" (service: {service})"
            
            return description if description.strip() else json.dumps(event_data)
        
        elif layer == "application":
            payload = event_data.get("payload", "")
            endpoint = event_data.get("endpoint", "")
            method = event_data.get("method", "")
            
            description = f"{method} {endpoint}: {payload}" if method and endpoint else payload
            return description if description else json.dumps(event_data)
        
        elif layer == "network":
            protocol = event_data.get("protocol", "")
            source_ip = event_data.get("source_ip", "")
            dest_ip = event_data.get("dest_ip", "")
            ports = event_data.get("ports_scanned", [])
            
            if ports:
                description = f"{protocol} traffic from {source_ip} to {dest_ip} scanning ports {ports}"
            else:
                description = f"{protocol} traffic from {source_ip} to {dest_ip}"
            
            return description if description else json.dumps(event_data)
        
        return str(event_data)
    
    def process_event(self, layer: str, event_data, event_description: str = None):
        """
        Process security event through integrated SLM + RAG pipeline
        
        Args:
            layer: Layer type ('application', 'container', or 'network')
            event_data: Raw log (dict, string, or any format)
            event_description: Optional custom text description for SLM
        
        Returns:
            Complete threat detection result with SLM + RAG context
        """
        
        # Validate layer
        if layer not in ["application", "container", "network"]:
            return {"error": f"Invalid layer: {layer}. Must be 'application', 'container', or 'network'."}
        
        # Load appropriate SLM model for this layer
        self.load_slm_for_layer(layer)
        
        # Extract event description if not provided
        if event_description is None:
            event_description = self.extract_event_description(layer, event_data)
        
        print(f"\n[LAYER] Processing {layer} layer event...")
        print(f"[SLM] Input description: {event_description[:100]}...")
        
        # Step 1: Get SLM prediction
        slm_result = self.slm.predict(layer, event_description)
        slm_confidence = slm_result.get("confidence", 0)
        slm_label = slm_result.get("label", "unknown")
        
        print(f"[SLM] Prediction: {slm_label}, Confidence: {slm_confidence:.4f}")
        
        # Step 2: Determine if we need RAG fallback
        use_rag = slm_confidence < 0.7 or slm_label == "unknown"
        
        # Convert event_data to dict if it's a string (for RAG processing)
        event_data_dict = {"raw_log": event_data} if isinstance(event_data, str) else event_data
        
        if use_rag:
            print(f"[RAG] Confidence < 0.7 or unknown → Triggering RAG fallback...")
            
            # Use RAG to find similar threats
            rag_result = self.rag_pipeline.process_event(
                layer=layer,
                event_data=event_data_dict,
                slm_prediction=slm_label,
                slm_confidence=slm_confidence
            )
            
            print(f"[RAG] Top match: {rag_result.get('threat_type')}, Confidence: {rag_result.get('confidence'):.4f}")
            
            # Combine SLM + RAG results
            final_result = {
                "detection_status": "THREAT_DETECTED",
                "layer": layer,
                "processing_flow": "SLM → RAG (Fallback)",
                "slm_analysis": {
                    "prediction": SLMThreatMapper.map_to_threat_name(layer, slm_label),
                    "confidence": slm_confidence,
                    "all_probabilities": slm_result.get("probabilities", {}),
                    "status": "LOW_CONFIDENCE" if slm_confidence < 0.7 else "UNKNOWN"
                },
                "rag_analysis": {
                    "top_match": rag_result.get("threat_type"),
                    "category": rag_result.get("threat_category"),
                    "confidence": rag_result.get("confidence"),
                    "mitre_id": rag_result.get("mitre_id"),
                    "similar_threats": rag_result.get("similar_threats", []),
                    "recommendations": rag_result.get("recommendations", [])
                },
                "final_verdict": {
                    "threat_type": rag_result.get("threat_type"),
                    "threat_category": rag_result.get("threat_category"),
                    "confidence": max(slm_confidence, rag_result.get("confidence", 0)),
                    "source": "SLM + RAG (Fallback)",
                    "mitre_id": rag_result.get("mitre_id")
                },
                "event_data": event_data
            }
        else:
            print(f"[SLM] High confidence → Using SLM prediction directly")
            
            # High confidence SLM prediction - use it directly
            final_result = {
                "detection_status": "THREAT_DETECTED",
                "layer": layer,
                "processing_flow": "SLM (Direct)",
                "slm_analysis": {
                    "prediction": SLMThreatMapper.map_to_threat_name(layer, slm_label),
                    "confidence": slm_confidence,
                    "all_probabilities": slm_result.get("probabilities", {}),
                    "status": "HIGH_CONFIDENCE"
                },
                "rag_analysis": None,
                "final_verdict": {
                    "threat_type": SLMThreatMapper.map_to_threat_name(layer, slm_label),
                    "confidence": slm_confidence,
                    "source": "SLM (Trained Model)",
                    "mitre_id": None
                },
                "event_data": event_data
            }
        
        return final_result


def get_layer_type():
    """Prompt user for layer type with validation"""
    print("\n" + "="*70)
    print("SELECT LAYER TYPE")
    print("="*70)
    print("Available layer types:")
    print("  1. container   - Docker container logs")
    print("  2. network     - Network traffic logs")
    print("  3. application - Application-level logs")
    print("="*70)
    
    valid_layers = ["container", "network", "application"]
    
    while True:
        layer = input("\nEnter layer type (container/network/application): ").strip().lower()
        
        if layer in valid_layers:
            print(f"✓ Layer type '{layer}' selected successfully!")
            return layer
        else:
            print(f"✗ Invalid layer type: '{layer}'")
            print(f"  Please enter one of: {', '.join(valid_layers)}")


def get_log_input():
    """Get log input from user (JSON or plain text)"""
    print("\n" + "="*70)
    print("ENTER LOG DATA")
    print("="*70)
    print("You can enter:")
    print("  • JSON format: {\"status\":\"exec_create: ps aux\", ...}")
    print("  • Plain text: Any log message or event description")
    print("\nPress Ctrl+D (Linux/Mac) or Ctrl+Z (Windows) when done:")
    print("="*70)
    print()
    
    log_input = sys.stdin.read().strip()
    
    # Try to parse as JSON first
    try:
        parsed_json = json.loads(log_input)
        print("✓ JSON format detected")
        return parsed_json
    except json.JSONDecodeError:
        # Not JSON, treat as plain text
        print("✓ Plain text format detected")
        return log_input


# Main entry point
if __name__ == "__main__":
    # Initialize integrated pip/workspaceeline
    model_dir = "/RAG"
    pipeline = IntegratedThreatDetectionPipeline(
        model_dir=model_dir,
        persist_dir="./chroma_db"
    )
    
    # Interactive mode: Get layer type first, then log
    try:
        # Step 1: Get layer type from user
        layer_type = get_layer_type()
        
        # Step 2: Get log input from user
        log_data = get_log_input()
        
        # Step 3: Process the event with specified layer
        result = pipeline.process_event(layer=layer_type, event_data=log_data)
        
        # Step 4: Display results
        print("\n" + "="*70)
        print(f"THREAT DETECTION RESULT - {layer_type.upper()} LAYER")
        print("="*70)
        print(json.dumps(result, indent=2))
        
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)